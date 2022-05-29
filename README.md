# Network-Traffic-Analyzer

## Introduction

C Implementation of Real-time Capture and Data Analysis of Network Data Packets

## Environment

1. Operating system：Linux
2. Programming language：C
3. Network traffic capture library：libpcap
4. Code editor：vscode

## Program running

1. **compile and link**

   ```makefile
   gcc -c catch_packet.c -o catch_packet.o
   gcc catch_packet.o -o catch -lpcap -lpthread
   
   gcc -c data_analysis.c -o data_analysis.o
   gcc data_analysis.o -o analyse -lpcap
   ```

2. **run the program**

   ```
   sudo ./catch <--catch> <file_out> <filter> <time>
   
   sudo ./analyse <--analyse> <file_in> <file_out> <time>
   ```

   



