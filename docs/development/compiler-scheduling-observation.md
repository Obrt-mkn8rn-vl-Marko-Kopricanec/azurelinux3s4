# Selected strict JMAP compilation observation

On 10 October 2026, two predefined developer builds of `mk8.email.Jmap` completed with zero warnings and errors. The selected source was commit `6c13695ff6fcbcf90277da2933afa0f08fa37407`. Each build used an independent regular byte copy of the same owned development snapshot and its existing reference metadata. All 1,272 mapped source inputs remained byte-identical before and after both builds; the original snapshot was unchanged.

| Explicit compiler scheduling | Command wall time | Reported analyzer time | Reported CA2000 time | Warnings / errors |
| --- | ---: | ---: | ---: | ---: |
| `/parallel+` | 209.907 s | 525.188 s | 238.711 s | 0 / 0 |
| `/parallel-` | 252.303 s | 176.475 s | 71.492 s | 0 / 0 |

Both actual child exit codes were zero, below the predefined 300-second allowance. The serial observation took about 20.2% longer. One sequential pair on copied warm references does not establish a general speedup, stability, representative resource requirement or the cause of any earlier timeout. Reported analyzer durations can overlap: the parallel total exceeds the entire command wall time. These values must not be interpreted as CPU time or added to command duration.

The selected SDK was 10.0.401. Its C# task binds `CompilerResponseFile` to response-file input; the two private files supplied only the respective scheduling option. The [Roslyn concurrency contract](https://learn.microsoft.com/en-us/dotnet/api/microsoft.codeanalysis.compilationoptions.concurrentbuild?view=roslyn-dotnet-5.0.0) describes permission to build a compilation using multiple threads. No compiler or deployment default was changed.

Both commands retained `AnalysisLevel=latest-all`, enabled .NET and build-time style analyzers, nullable analysis, warnings as errors, the original specialist analyzer stack, disabled shared compilation, and serial MSBuild project scheduling. Each complete compiler command contained the same 34 analyzer arguments with identical file hashes. The completed timing report attributes the largest recorded analyzer cost to CA2000 disposal analysis. No rule was disabled or suppressed to obtain either result.

The diagnostic selected a library build with `--no-restore`, `--no-incremental` and `BuildProjectReferences=false`. Existing compiled reference metadata was copied and consumed; dependencies were not rebuilt or freshly restored. Literal command inspection identified 196 reference arguments, 131 source-file arguments, seven additional files, two analyzer configurations and one response file in each leg. Their retained metadata/hash observations are later data points, not proof of what every native load consumed or of authenticated package provenance.

This result closes neither application publish nor full-test, native startup, authenticated release or server-readiness gates. Earlier worker and gateway publish deadlines, the earlier incomplete JMAP diagnostic, other application failures and wider installer failures retain their original dispositions. This experiment supplies new completed selected-library analyzer timing evidence; it does not repair, supersede or explain those historical failures.

Two own inspection/setup failures remain separately recorded: the first setup compared byte-only rows with mode-bearing metadata and stopped before copying or launching the SDK; a later data inspector initially resolved project-relative compiler paths from the launch directory. Neither changed application source or compiler results. The corrected inspections preserve the original failures and disclose their scope.

Raw commands, channels, numerical waits, copy inventories, source maps, compiler input points, analyzer hashes and qualifications are retained in the ignored internal `strict-compiler-diagnostic-work` packet and its checkpoint report. This document records development research only. It authorizes no account provisioning, service operation, installation, network change or deployment.
