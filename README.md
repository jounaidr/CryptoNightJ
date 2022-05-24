# CryptoNightJ
An unoptimised Java native implementation of the CryptoNight proof of work algorithm, see [CryptoNightJNI](https://github.com/jounaidr/CryptoNightJNI) for an optimal solution.

The algorithms implementation can be found in: [Cryptonight.java](https://github.com/jounaidr/CryptoNightJ/blob/main/src/main/java/Cryptonight.java) with various other hashing packages used.

### Algorithm Overview
The CryptoNight algorithm consists of three sections: scratchpad initialisation, memory-hard loop and results calculation. The following three diagrams (based on the Cryptonote Standard 2013) provide an overview on how the algorithm functions. See the [Monero docs](https://monerodocs.org/proof-of-work/cryptonight/) or [JRC writeup](https://github.com/jounaidr/reports-archive/blob/main/DISS_REPORT.pdf) for more info.


**Scratchpad Initialisation**

<p align="center" width="100%">
    <img width="33%" src="https://github.com/jounaidr/CryptoNightJ/blob/main/docs/resources/scratchpad_initializatin.png"> 
</p>

**Memory-hard Loop**

![mem_hard_loop_trans](https://github.com/jounaidr/CryptoNightJ/blob/main/docs/resources/mem_hard_loop_trans.png)

**Results Calculation**

![results_calc](https://github.com/jounaidr/CryptoNightJ/blob/main/docs/resources/results_calc.png)

### Dependencies
The project structure and dependencies can be seen in the following diagram:
![CryptoNightJ_expanded_dependancy_diagram](https://github.com/jounaidr/CryptoNightJ/blob/main/docs/resources/CryptoNightJ_expanded_dependancy_diagram.png)

### TODOs
- Optimisation throughout (see code)
- Refactor Cryptonight.java to implement hashing digest interface as to stay consistent with other Java hashing algorithms
