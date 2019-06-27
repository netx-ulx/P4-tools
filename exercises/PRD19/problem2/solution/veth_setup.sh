#!/bin/bash

ip link add dev Node1 address 00:00:00:00:01:01 type veth peer name Node2 address 00:00:00:00:02:02

ip link set Node1 up
ip link set Node2 up