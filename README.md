# L-TLS: Lightweight TLS for the New IoT World

This tool is used to create a list of possible TLS configurations for a device. It also provides various statistics regarding 
the configurations. These configurations mainly refer to the ciphersuite that is chosen during the Handshake protocol. The tool 
is composed of two main modules:

* Data acquisition module [(l-tls)](./l-tls): Configures which metrics are evaluated and generates data
* Data analysis module [(tools)](./tools): Analyses data and generates graphs and tables

## Data Acquisition Module

This module uses the [Mbed TLS](https://tls.mbed.org/) to implement the TLS protocol. The server and client in the acquisition 
module also make use of the Mbed TLS library. There is also a measurement library that implements the measurements of the 
metrics.

The measurement library uses a structure similar to Mbed TLS and allows the implementation of new metrics. This is done by 
creation a new metric module (the structure is the same as the other modules) and adding it to the wrapper module
[(measure_wrap.c)](./l-tls/measurement/library).

## Data Analysis Module

The data analysis can be done by focusing on algorithm types or security services provided. Two sets of tools were created to 
make the analysis:

* Security Services:
  * Analyser: Analyses the performance of security services used in the Handshake protocol for a set of ciphersuites
  * Calculator: Calculates the overall performance of all security services used in the Handshake and/or Record protocol
  for a set of ciphersuites
  * Comparator: Compares the performance of algorithms that provide a certain security service
  * Profiler: Automates the process of acquiring and analysing data. It uses the data acquisition module to generate data and
  runs all other tools to generate statistics

* Algorithms:
  * Comparator: Compares the performance of algorithms within the same type (cipher, message digest or key exchange)
  * Plotter: Analyses the provided dataset of all algorithms within the same type
  * Profiler: Automates the process of acquiring and analysing data. It uses the data acquisition module to generate data and
  runs all other tools to generate statistics

A graphical user interface (GUI) was created to make it easier to use the tool. Alternatively, each tool can be used from a
command terminal.

# Important Notes

* The Mbed TLS library and the communication peers share a configuration file that is used to select which Mbed TLS modules and 
measurement features are going to be used
* The modules can be used separately, i.e. the data can be acquired in the target device and analysed in another machine or they 
can be used simultaneously.
* The modules are not synched, i.e. the data analysis module does not configure the data acquisition module. As such, the user 
needs to make sure the data that is going to be analysed is being generated by the acquisition module

# Running and Requirements

## Data Acquisition Module

To run this module the following requirements are needs:

* The target device needs to:
  * Establish TCP sockets so that the server/client can communicate
  * Create CSV files in order to save the generated data
  * With the default configuration, this module occupies around 2.4 MiB. This value includes the Mbed TLS library (around 1.2 
  MiB) and the server/client (around 1.2 MiB)
  * To use the `PAPI` library the system needs to have the required counters available. Follow these
  [instructions](https://bitbucket.org/icl/papi/wiki/Downloading-and-Installing-PAPI.md) to configure PAPI.
* `C compiler` installed, such as `gcc`

## Data Analysis Module

* The device needs to be able to execute graphical applications to use the GUI
* `Python 3.6` installed (it needs to be `3.6` due to the use of the
[formatted string literals](https://www.python.org/dev/peps/pep-0498/). If you replace those in the code you can use older 
`Python 3` versions)

To install the dependencies, run the following command: `pip install -r requirements.txt`. After the instalation is done,
you can start using the tools.

# Usage

## Data Acquisition Module

This module can be used separately. All instructions found in this section are relative to the [l-tls](./l-tls) directory.

Before compiling the module, you need to configure which algorithms are going to be measured and which metrics are going to be used.
To configure the algorithms, go to the config file in the [l-tls/tls_algs](./l-tls/tls_algs) directory and enable or disable the intended
MEASURE_XXXXX macros. Each macro affects one type of algorithm. To configure the metrics go to the config file in the
[l-tls/measurement/include/measurement](./l-tls/measurement/include/measurement) directory and enable or disable the intended
MEASUREMENT_XXXXX_C macros. Each macro affects one metric.

After the configuration is done, you need to compile the C code by running:

```
make tls_als
```

The `Makefile` also contains other compilation commands. After the compilation is done, run the client and the server. These endpoints
will execute the Handshake protocol in a loop and the Record protocol in another loop to generate the data.

They need to be used in two separate command prompts. To execute them, run the following commands in each command prompt:

```
./tls_algs/server.out ciphersuite=<ciphersuite_name> [sec_lvl=<initial_lvl>] [max_sec_lvl=<final_lvl>]
                      [msg_size=<initial_size>] [max_msg_size=<final_size>] [n_tests=<n_tests>]
                      [path=<data_directory>] [debug_lvl=<debug_lvl>]

./tls_algs/client.out ciphersuite=<ciphersuite_name> [sec_lvl=<initial_lvl>] [max_sec_lvl=<final_lvl>]
                      [msg_size=<initial_size>] [max_msg_size=<final_size>] [n_tests=<n_tests>]
                      [path=<data_directory>] [debug_lvl=<debug_lvl>]


positional arguments:
  ciphersuite=<ciphersuite_name>    Name of the ciphersuite to be used

optional arguments:
  sec_lvl=<initial_lvl>             Minimum security level to be used (From 0 to 4, 0 is not
                                    considered secure)
  max_sec_lvl=<final_lvl>           Maximum security level to be used (From 0 to 4, 0 is not
                                    considered secure)
  msg_size=<initial_size>           Minimum message size to be used, in bytes (From 32 to 16384 = 16KB)
  max_msg_size=<final_size>         Maximum message size to be used, in bytes (From 32 to 16384 = 16KB)
  n_tests=<n_tests>                 Number of iterations for each security level or message size
  path=<data_directory>             Name of the directory where the data will be stored. Root
                                    directory is docs/
  debug_lvl=<debug_lvl>             Mbed TLS level of debug (From 0 to 5, where 0 is none and 5 is the
                                    maximum)
```

## Data Analysis Module

Although there are many different tools, most of the arguments used are similar within the same set of tools. All tools also
have a `-h`/`--help` option that shows how to use them. Below are the instructions on how to use each tool.

Security Services Tools:

```
services_analyser.py [-w <filter_weight>] [-H] [-a] [-k] [-p] <path_to_data>

services_calculator.py [-w <filter_weight>] [-c] [-i] [-a] [-k] [-p] <path_to_data>

services_comparator.py [-w <filter_weight>] [-c] [-i] [-a] [-k] [-p] <path_to_data> <services_list>

services_profiler.py [-t <compilation_target>] [-w <filter_weight>] [-s <initial_lvl>,<final_lvl>]
                     [-m <initial_size>,<final_size>] [-n <n_tests>] [-d <data_directory>] [-H] [-c]
                     [-i] [-a] [-k] [-p] <services_list>


positional arguments:
  path_to_data              Relative path from the ./docs directory where the data is stored
  services_list             File with list of security services and algorithms that provide them.
                            Example found in examples/ke_servs.txt

optional arguments:
  -h, --help                show help message and exit
  -t <compilation_target>, --target=<compilation_target>
                            Path to endpoint implementation relative to l-tls/ directory. Default is
                            tls_algs
  -w <filter_weight>, --weight=<filter_weight>
                            Weight of the z-score filter parameter. The default is 2. filter_weight=0
                            means no data is filtered
  -s <initial_lvl>,<final_lvl>, --sec_lvl=<initial_lvl>,<final_lvl>
                            Range of security levels to be considered. From 0 to 4, where 0 is
                            considered insecure and 4 is maximum security
  -m <initial_size>,<final_size>, --message_size=<initial_size>,<final_size>
                            Range of message sizes to be considered, in bytes. From 32 to 16384 (16KB)
  -n <n_tests>, --n_tests=<n_tests>
                            Number of iterations
  -d <data_directory>, --data_path=<data_directory>
                            Name of the directory where the data will be stored and used. Root
                            directory is docs/
  -H, --handshake           Analyse overall handshake performance
  -c, --conf                Analyse performance of the confidentiality security service
  -i, --int                 Analyse performance of the integrity security service
  -a, --auth                Analyse performance of the authentication security service
  -k, --ke                  Analyse performance of the key establishment security service
  -p, --pfs                 Analyse performance of the perfect forward secrecy security service
```

Algorithms Tools:

```
algs_comparator.py [-w <filter_weight>] [-c] [-m] [-k] <path_to_data> <algorithm_list>

algs_plotter.py [-w <filter_weight>] [-c] [-m] [-k] <path_to_data>

algs_profiler.py [-t <compilation_target>] [-w <filter_weight>] [-s <initial_lvl>,<final_lvl>]
                 [-i <initial_size>,<final_size>] [-n <n_tests>] [-d <data_directory>] [-c] [-m] [-k]
                 <services_list>


positional arguments:
  path_to_data              Relative path from the ./docs directory where the data is stored
  algorithm_list            File with list of algorithm types and algorithms that belong in them.
                            Example found in examples/ke_algs.txt

optional arguments:
  -h, --help                show help message and exit
  -t <compilation_target>, --target=<compilation_target>
                            Path to endpoint implementation relative to l-tls/ directory. Default is
                            tls_algs
  -w <filter_weight>, --weight=<filter_weight>
                            Weight of the z-score filter parameter. The default is 2. filter_weight=0
                            means no data is filtered
  -c, --cipher              Analyse performance of cipher algorithms
  -m, --md                  Analyse performance of message digest algorithms
  -k, --ke                  Analyse performance of key extablishment algorithms
  -s <initial_lvl>,<final_lvl>, --sec_lvl=<initial_lvl>,<final_lvl>
                            Range of security levels to be considered. From 0 to 4, where 0 is
                            considered insecure and 4 is maximum security
  -m <initial_size>,<final_size>, --message_size=<initial_size>,<final_size>
                            Range of message sizes to be considered, in bytes. From 32 to 16384 (16KB)
  -n <n_tests>, --n_tests=<n_tests>
                            Number of iterations
  -d <data_directory>, --data_path=<data_directory>
                            Name of the directory where the data will be stored and used. Root
                            directory is docs/
```

Graphical User Interface:

The GUI does not have any arguments. You only need to run `python3 ltls.py` to execute it.

The GUI is divided in two sections: the services section and the algorithms section. Each section has a set of checkboxes and buttons.
The checkboxes are used to select which algorithms will be analysed. There are 3 buttons in each section: `Edit Services/Algorithms`,
`Acquire Data` and `Generate Statistics`.

The `Edit Services/Algorithms` button allows you to add or remove algorithms from a service/algortihm type category. The `Acquire Data`
allows you to generate new data while the `Generate Statistics` allows you to generate statistics from previously generated data. Both
these functionalities execute the respective `profiler.py` tool.