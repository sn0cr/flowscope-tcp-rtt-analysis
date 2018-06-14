# flowscope-tcp-rtt-analysis
Use [FlowScope](https://github.com/pudelkoM/FlowScope) to analyse the RTT of TCP flows

## About used software
We used FlowScope commit version *7beb980* and it can be found [here](https://github.com/pudelkoM/FlowScope). To use the same version as during the development of this module, run (after cloning the repository):
```sh
  $ git checkout 7beb980
```

# Usage

  1. Clone [FlowScope](https://github.com/pudelkoM/FlowScope):

    ```sh
      $ git clone --recursive https://github.com/pudelkoM/FlowScope
      $ git checkout 7beb980
      $ # follow instructions in the FlowScope readme
    ```
  1. Clone [this repository](https://github.com/sn0cr/flowscope-tcp-rtt-analysis):

    ```sh
      $ git clone https://github.com/sn0cr/flowscope-tcp-rtt-analysis.git
    ```
  1. Install FlowScope:

    ```sh
      $ cd FlowScope
      $ # follow instructions in the FlowScope Readme
    ```
  1. Create a 'json' and 'pcaps' folder to store the results:

    ```sh
      $ mkdir json
      $ mkdir pcaps
    ```
  1. Run Flowscope:

    ```sh
      $ ./libmoon/build/libmoon lua/flowscope.lua --path ./pcaps ../flowscope-tcp-rtt-analysis/src/TCPRTTTimeAnalysis_avg_w_seq.lua 0
    ```


# Licence (MIT License)

Copyright (c) 2018 Christian Wahl

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
