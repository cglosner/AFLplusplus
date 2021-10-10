# American Fuzzy Lop plus plus (AFL++)

<img align="right" src="https://raw.githubusercontent.com/andreafioraldi/AFLplusplus-website/master/static/logo_256x256.png" alt="AFL++ logo">

Release version: [3.14c](https://github.com/AFLplusplus/AFLplusplus/releases)

GitHub version: 3.15a

Repository: [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

AFL++ is maintained by:

* Marc "van Hauser" Heuse <mh@mh-sec.de>,
* Heiko "hexcoder-" Eißfeldt <heiko.eissfeldt@hexco.de>,
* Andrea Fioraldi <andreafioraldi@gmail.com> and
* Dominik Maier <mail@dmnk.co>.

Originally developed by Michał "lcamtuf" Zalewski.

AFL++ is a superior fork to Google's AFL - more speed, more and better mutations, more and better instrumentation, custom module support, etc.

You are free to copy, modify, and distribute AFL++ with attribution under the terms of the Apache-2.0 License. See the [LICENSE](LICENSE) for details.

## Getting started

Here is some information to get you started:

* For releases, please see the [Releases](https://github.com/AFLplusplus/AFLplusplus/releases) tab and [branches](docs/branches.md). Also take a look at the list of [important changes in AFL++](docs/important_changes.md).
* If you want to use AFL++ for your academic work, check the [papers page](https://aflplus.plus/papers/) on the website.
* To cite our work, look at the [Cite](#cite) section.
* For comparisons, use the fuzzbench `aflplusplus` setup, or use `afl-clang-fast` with `AFL_LLVM_CMPLOG=1`. You can find the `aflplusplus` default configuration on Google's [fuzzbench](https://github.com/google/fuzzbench/tree/master/fuzzers/aflplusplus).
* To get you started with tutorials, go to [docs/tutorials.md](docs/tutorials.md).

## Building and installing AFL++

To have AFL++ easily available with everything compiled, pull the image directly from the Docker Hub:

```shell
docker pull aflplusplus/aflplusplus
docker run -ti -v /location/of/your/target:/src aflplusplus/aflplusplus
```

This image is automatically generated when a push to the stable repo happens (see [docs/branches.md](docs/branches.md)).
You will find your target source code in `/src` in the container.

To build AFL++ yourself, continue at [docs/INSTALL.md](docs/INSTALL.md).

## Quick start: Fuzzing with AFL++

*NOTE: Before you start, please read about the [common sense risks of fuzzing](docs/common_sense_risks.md).*

This is a quick start for fuzzing targets with the source code available.
To read about the process in detail, see [docs/fuzzing_expert.md](docs/fuzzing_expert.md).

To learn about fuzzing other targets, see:
* Binary-only targets: [docs/fuzzing_binary-only_targets.md](docs/fuzzing_binary-only_targets.md)
* Network services: [docs/best_practices.md#fuzzing-a-network-service](docs/best_practices.md#fuzzing-a-network-service)
* GUI programs: [docs/best_practices.md#fuzzing-a-gui-program](docs/best_practices.md#fuzzing-a-gui-program)

Step-by-step quick start:

1. Compile the program or library to be fuzzed using `afl-cc`.
A common way to do this would be:

        CC=/path/to/afl-cc CXX=/path/to/afl-c++ ./configure --disable-shared
        make clean all

2. Get a small but valid input file that makes sense to the program.
When fuzzing verbose syntax (SQL, HTTP, etc), create a dictionary as described in [dictionaries/README.md](dictionaries/README.md), too.

3. If the program reads from stdin, run `afl-fuzz` like so:

```
   ./afl-fuzz -i seeds_dir -o output_dir -- \
     /path/to/tested/program [...program's cmdline...]
```

   To add a dictionary, add `-x /path/to/dictionary.txt` to afl-fuzz.

   If the program takes input from a file, you can put `@@` in the program's
   command line; AFL will put an auto-generated file name in there for you.

4. Investigate anything shown in red in the fuzzer UI by promptly consulting [docs/status_screen.md](docs/status_screen.md).

5. You will find found crashes and hangs in the subdirectories `crashes/` and
   `hangs/` in the `-o output_dir` directory. You can replay the crashes by
   feeding them to the target, e.g.:
   `cat output_dir/crashes/id:000000,* | /path/to/tested/program [...program's cmdline...]`
   You can generate cores or use gdb directly to follow up the crashes.

## Contact

Questions? Concerns? Bug reports?

* The contributors can be reached via [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus).
* Take a look at our [FAQ](docs/FAQ.md). If you find an interesting or important question missing, submit it via
[https://github.com/AFLplusplus/AFLplusplus/discussions](https://github.com/AFLplusplus/AFLplusplus/discussions).
* There is a mailing list for the AFL/AFL++ project ([browse archive](https://groups.google.com/group/afl-users)). To compare notes with other users or to get notified about major new features, send an email to <afl-users+subscribe@googlegroups.com>.
* Or join the [Awesome Fuzzing](https://discord.gg/gCraWct) Discord server.

## Help wanted

We have several [ideas](docs/ideas.md) we would like to see in AFL++ to make it even better.
However, we already work on so many things that we do not have the time for all the big ideas.

This can be your way to support and contribute to AFL++ - extend it to do something cool.

For everyone who wants to contribute (and send pull requests), please read our [contributing guidelines](CONTRIBUTING.md) before your submit.

## Special thanks

Many of the improvements to the original AFL and AFL++ wouldn't be possible without feedback, bug reports, or patches from our contributors.

Thank you!
(For people sending pull requests - please add yourself to this list :-)

<details>

  <summary>List of contributors</summary>

  ```
    Jann Horn                             Hanno Boeck
    Felix Groebert                        Jakub Wilk
    Richard W. M. Jones                   Alexander Cherepanov
    Tom Ritter                            Hovik Manucharyan
    Sebastian Roschke                     Eberhard Mattes
    Padraig Brady                         Ben Laurie
    @dronesec                             Luca Barbato
    Tobias Ospelt                         Thomas Jarosch
    Martin Carpenter                      Mudge Zatko
    Joe Zbiciak                           Ryan Govostes
    Michael Rash                          William Robinet
    Jonathan Gray                         Filipe Cabecinhas
    Nico Weber                            Jodie Cunningham
    Andrew Griffiths                      Parker Thompson
    Jonathan Neuschaefer                  Tyler Nighswander
    Ben Nagy                              Samir Aguiar
    Aidan Thornton                        Aleksandar Nikolich
    Sam Hakim                             Laszlo Szekeres
    David A. Wheeler                      Turo Lamminen
    Andreas Stieger                       Richard Godbee
    Louis Dassy                           teor2345
    Alex Moneger                          Dmitry Vyukov
    Keegan McAllister                     Kostya Serebryany
    Richo Healey                          Martijn Bogaard
    rc0r                                  Jonathan Foote
    Christian Holler                      Dominique Pelle
    Jacek Wielemborek                     Leo Barnes
    Jeremy Barnes                         Jeff Trull
    Guillaume Endignoux                   ilovezfs
    Daniel Godas-Lopez                    Franjo Ivancic
    Austin Seipp                          Daniel Komaromy
    Daniel Binderman                      Jonathan Metzman
    Vegard Nossum                         Jan Kneschke
    Kurt Roeckx                           Marcel Boehme
    Van-Thuan Pham                        Abhik Roychoudhury
    Joshua J. Drake                       Toby Hutton
    Rene Freingruber                      Sergey Davidoff
    Sami Liedes                           Craig Young
    Andrzej Jackowski                     Daniel Hodson
    Nathan Voss                           Dominik Maier
    Andrea Biondo                         Vincent Le Garrec
    Khaled Yakdan                         Kuang-che Wu
    Josephine Calliotte                   Konrad Welc
    Thomas Rooijakkers                    David Carlier
    Ruben ten Hove                        Joey Jiao
    fuzzah
  ```

</details>

## Cite

If you use AFL++ in scientific work, consider citing [our paper](https://www.usenix.org/conference/woot20/presentation/fioraldi) presented at WOOT'20:

    Andrea Fioraldi, Dominik Maier, Heiko Eißfeldt, and Marc Heuse. “AFL++: Combining incremental steps of fuzzing research”. In 14th USENIX Workshop on Offensive Technologies (WOOT 20). USENIX Association, Aug. 2020.

<details>

<summary>BibTeX</summary>

  ```bibtex
  @inproceedings {AFLplusplus-Woot20,
  author = {Andrea Fioraldi and Dominik Maier and Heiko Ei{\ss}feldt and Marc Heuse},
  title = {{AFL++}: Combining Incremental Steps of Fuzzing Research},
  booktitle = {14th {USENIX} Workshop on Offensive Technologies ({WOOT} 20)},
  year = {2020},
  publisher = {{USENIX} Association},
  month = aug,
  }
  ```

</details>
