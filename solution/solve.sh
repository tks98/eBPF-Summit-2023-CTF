#!/bin/bash

# Convert ASCII values to string
ascii_to_str() {
  local arr=($@)
  local str=""
  for ascii in "${arr[@]}"; do
    str="$str$(printf "\x$(printf %x $ascii)")"
  done
  echo "$str"
}

# Loop through each eBPF program loaded into the kernel
for prog_id in $(sudo bpftool prog list | grep -oP '^\d+'); do
  
  # Loop through each map associated with the eBPF program
  for map_id in $(sudo bpftool prog show id $prog_id | grep -oP 'map_ids \K[\d,]+' | tr ',' ' '); do
    
    echo "Showing details for Map ID: $map_id"
    sudo bpftool map show id $map_id;
    echo "Dumping contents for Map ID: $map_id"
    
    # Dump map content
    map_content=$(sudo bpftool map dump id $map_id)

    # Check if the map_content contains 'pid_string'
    if [[ $map_content == *"pid_string"* ]]; then
      echo "Found pid_string in Map ID: $map_id"

      # Parse ASCII values of pid_string into an array
      pid_ascii_values=($(echo $map_content | grep -oP '"pid_string": \[\K[^\]]+' | tr ',' ' '))

      # Convert ASCII values to string to get the PID
      pid=$(ascii_to_str "${pid_ascii_values[@]}")
      echo "Parsed PID: $pid"

      # Kill the parsed PID
      echo "Killing PID: $pid"
      sudo kill $pid

      # Sleep for 1 second to allow the hidden binary to update the file before terminating
      echo "Sleeping for 1 second before reading the flag..."
      sleep 1

      # Read the flag from /ebpf.summit
      echo "Reading flag from /ebpf.summit"
      cat /ebpf.summit
    fi

    echo "------"
  done;
done
