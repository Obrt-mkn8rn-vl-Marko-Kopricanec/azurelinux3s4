using System;
using System.IO;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace S4.ManagedImports;

// A developer metadata reader for explicitly trusted build outputs. PEReader is
// not a hostile-input security boundary. No input assembly is loaded or run.
internal static class Program
{
    private const int MaximumImageBytes = 128 * 1024 * 1024;
    private const long MaximumTotalBytes = 256L * 1024 * 1024;
    private const int MaximumOutputBytes = 1024 * 1024;

    private static int Main(string[] arguments)
    {
        try
        {
            if (arguments.Length != 0)
            {
                throw new InvalidDataException("This helper accepts only framed standard input.");
            }

            byte[] result;
            using (Stream input = Console.OpenStandardInput())
            {
                result = InspectBatch(input);
            }

            // Publish only after every image, the final EOF and owned input
            // disposal succeeded. An output failure can still leave partial JSON.
            using Stream output = Console.OpenStandardOutput();
            output.Write(result);
            output.WriteByte((byte)'\n');
            output.Flush();
            return 0;
        }
        catch (Exception error) when (error is IOException or InvalidDataException or BadImageFormatException
            or ArgumentException or InvalidOperationException or OverflowException)
        {
            Console.Error.WriteLine("Managed import inspection refused");
            return 75;
        }
    }

    private static byte[] InspectBatch(Stream input)
    {
        using var reader = new BinaryReader(input, Encoding.UTF8, leaveOpen: true);
        if (!reader.ReadBytes(8).AsSpan().SequenceEqual("S4PINV1\n"u8))
        {
            throw new InvalidDataException("Unsupported input framing.");
        }

        uint count = reader.ReadUInt32();
        if (count is < 1 or > 512)
        {
            throw new InvalidDataException("Image count bound.");
        }

        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(output))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema", 1);
            writer.WriteString("scope", "MANAGED PINVOKE METADATA DECLARATIONS");
            writer.WriteStartArray("images");
            long total = 0;
            for (uint index = 0; index < count; index++)
            {
                (byte[] image, byte[] digest) = ReadImage(reader, index, ref total);
                WriteImage(writer, index, image, digest);
                writer.Flush();
                CheckOutputBound(output);
            }

            if (input.ReadByte() != -1)
            {
                throw new InvalidDataException("Trailing framed input.");
            }

            writer.WriteEndArray();
            writer.WriteStartObject("authority");
            writer.WriteBoolean("input_assemblies_loaded", value: false);
            writer.WriteBoolean("native_imports_called", value: false);
            writer.WriteBoolean("native_library_resolution_proven", value: false);
            writer.WriteBoolean("abi_or_marshalling_compatible", value: false);
            writer.WriteBoolean("runtime_authenticated", value: false);
            writer.WriteBoolean("hostile_metadata_safe", value: false);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        CheckOutputBound(output);
        return output.ToArray();
    }

    private static (byte[] Image, byte[] Digest) ReadImage(BinaryReader reader, uint index, ref long total)
    {
        uint ordinal = reader.ReadUInt32();
        ulong length = reader.ReadUInt64();
        if (ordinal != index || length is < 64 or > MaximumImageBytes)
        {
            throw new InvalidDataException("Image identity or size bound.");
        }

        total = checked(total + (long)length);
        if (total > MaximumTotalBytes)
        {
            throw new InvalidDataException("Total image byte bound.");
        }

        byte[] expected = reader.ReadBytes(SHA256.HashSizeInBytes);
        byte[] image = reader.ReadBytes((int)length);
        byte[] digest = SHA256.HashData(image);
        if (image.Length != (int)length || !digest.AsSpan().SequenceEqual(expected))
        {
            throw new InvalidDataException("Complete original image hash required.");
        }

        return (image, digest);
    }

    private static void WriteImage(Utf8JsonWriter writer, uint ordinal, byte[] image, byte[] digest)
    {
        using var stream = new MemoryStream(image, writable: false);
        using var pe = new PEReader(stream, PEStreamOptions.LeaveOpen);
        if (!pe.HasMetadata)
        {
            throw new InvalidDataException("CLI metadata required.");
        }

        MetadataReader metadata = pe.GetMetadataReader(MetadataReaderOptions.None);
        int methods = metadata.GetTableRowCount(TableIndex.MethodDef);
        int modules = metadata.GetTableRowCount(TableIndex.ModuleRef);
        int maps = metadata.GetTableRowCount(TableIndex.ImplMap);
        if (!metadata.IsAssembly || methods > 262144 || modules > 4096 || maps > 16384)
        {
            throw new InvalidDataException("Supported complete assembly table bounds required.");
        }

        writer.WriteStartObject();
        writer.WriteNumber("ordinal", ordinal);
        writer.WriteNumber("bytes", image.Length);
        writer.WriteString("sha256", Convert.ToHexStringLower(digest));
        writer.WriteString("assembly_name", ReadName(metadata, metadata.GetAssemblyDefinition().Name));
        writer.WriteNumber("method_rows", methods);
        writer.WriteNumber("implmap_rows", maps);
        writer.WriteStartArray("module_references");
        for (int row = 1; row <= modules; row++)
        {
            ModuleReference module = metadata.GetModuleReference(MetadataTokens.ModuleReferenceHandle(row));
            writer.WriteStringValue(ReadName(metadata, module.Name));
            CheckWriterBound(writer);
        }

        writer.WriteEndArray();
        WriteImports(writer, metadata, modules, maps);
        writer.WriteEndObject();
    }

    private static void WriteImports(Utf8JsonWriter writer, MetadataReader metadata, int modules, int maps)
    {
        writer.WriteStartArray("imports");
        int observed = 0;
        foreach (MethodDefinitionHandle handle in metadata.MethodDefinitions)
        {
            MethodDefinition method = metadata.GetMethodDefinition(handle);
            if (!method.Attributes.HasFlag(MethodAttributes.PinvokeImpl))
            {
                continue;
            }

            if (++observed > maps)
            {
                throw new InvalidDataException("Import row count mismatch.");
            }

            WriteImport(writer, metadata, handle, method, modules);
        }

        if (observed != maps)
        {
            throw new InvalidDataException("Every ImplMap row must have one supported PInvoke method.");
        }

        writer.WriteEndArray();
    }

    private static void WriteImport(Utf8JsonWriter writer, MetadataReader metadata,
        MethodDefinitionHandle handle, MethodDefinition method, int modules)
    {
        MethodImport import = method.GetImport();
        int moduleRow = MetadataTokens.GetRowNumber(import.Module);
        int flags = (int)import.Attributes;
        int convention = flags & 0x700;
        if (moduleRow < 1 || moduleRow > modules || import.Name.IsNil
            || !method.Attributes.HasFlag(MethodAttributes.Static)
            || method.RelativeVirtualAddress != 0 || (flags & ~0x3777) != 0
            || (flags & 0x30) == 0x30 || (flags & 0x3000) == 0x3000
            || convention is < 0x100 or > 0x500)
        {
            throw new InvalidDataException("Supported complete method import required.");
        }

        BlobReader signature = metadata.GetBlobReader(method.Signature);
        if (signature.Length is < 1 or > 65536)
        {
            throw new InvalidDataException("Bounded complete import signature required.");
        }

        byte[] signatureBytes = signature.ReadBytes(signature.Length);
        writer.WriteStartObject();
        writer.WriteNumber("method_token", MetadataTokens.GetToken(handle));
        writer.WriteString("method_name", ReadName(metadata, method.Name));
        writer.WriteString("module", ReadName(metadata, metadata.GetModuleReference(import.Module).Name));
        writer.WriteString("entry_point", ReadName(metadata, import.Name));
        writer.WriteNumber("mapping_flags", flags);
        writer.WriteNumber("method_flags", (int)method.Attributes);
        writer.WriteNumber("implementation_flags", (int)method.ImplAttributes);
        writer.WriteNumber("signature_bytes", signatureBytes.Length);
        writer.WriteString("signature_sha256", Convert.ToHexStringLower(SHA256.HashData(signatureBytes)));
        writer.WriteEndObject();
        CheckWriterBound(writer);
    }

    private static string ReadName(MetadataReader metadata, StringHandle handle)
    {
        string value = metadata.GetString(handle);
        if (value.Length is < 1 or > 4096)
        {
            throw new InvalidDataException("Bounded nonempty metadata name required.");
        }

        foreach (char item in value)
        {
            if (item is < ' ' or > '~')
            {
                throw new InvalidDataException("Printable ASCII metadata name required.");
            }
        }

        return value;
    }

    private static void CheckOutputBound(MemoryStream output)
    {
        if (output.Length >= MaximumOutputBytes)
        {
            throw new InvalidDataException("Complete report byte bound.");
        }
    }

    private static void CheckWriterBound(Utf8JsonWriter writer)
    {
        if (writer.BytesCommitted + writer.BytesPending >= MaximumOutputBytes)
        {
            throw new InvalidDataException("Import report byte bound.");
        }
    }
}
