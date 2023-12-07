#!/bin/sh
apt-get update  # To get the latest package lists
apt-get install gcc-multilib gdb python3-pip git -y
pip3 install capstone pygdbmi
git clone https://github.com/JonathanSalwan/ROPgadget.git
