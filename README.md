# Key Management and Service Framework for QKD networks

## Overview
This repository provides the open-source implementation of methodologies described in the paper “Decentralized Key Management and Service in Quantum Key Distribution Networks: An Experimental Implementation”. It includes the following components:

1. The proposed **AUTO rate control scheme**, designed for dynamic and efficient rate adjustments in QKD networks.
2. The **QKD-TL scheme**, leveraging the ECN mechanism for congestion control as a comparative baseline.
3. An **Active Queue Management (AQM) scheme**, aimed at enhancing network performance by managing packet queues dynamically.
4. A **congestion control scheme** based on the Resource Reservation Protocol, optimizing resource allocation in network traffic scenarios.

## Usage Instructions

### Compilation
To compile the source files, use the following command:
```bash
g++ -o output_file source_file.cpp
```
Replace `output_file` with your desired executable name and `source_file.cpp` with the relevant source file. Ensure that all dependencies are correctly included in your environment.

### Configuration

#### Topology and Routing Configuration
This project implements a distributed architecture suitable for custom network topologies. The provided example demonstrates a seven-node network topology, chosen for its ability to model diverse network conditions and interactions within a distributed quantum key distribution (QKD) environment. This topology allows for realistic simulations of both key packet transmission and congestion scenarios, providing a robust framework for evaluating the implemented methodologies. It comprises:

1. A **barbell topology** for key data packet transmission (PC1-PC4, PC6-PC7).
2. A **simulated QKD key injection node** (PC5), responsible for introducing quantum keys into the network.

The simulated injection node utilizes `begin` and `end` commands to mark the start and end of experiments for precise control.

##### Node Configuration
The IP addresses for the example topology nodes are predefined as follows:

- **PC1**: `{"192.168.190.128", "192.168.194.128", "192.168.195.128", "192.168.196.129"}`
- **PC2**: `{"192.168.190.129", "192.168.191.128", "192.168.192.128", "192.168.194.133"}`
- **PC3**: `{"192.168.191.129", "192.168.194.131"}`
- **PC4**: `{"192.168.192.129", "192.168.194.134"}`
- **PC5**: `{"192.168.194.129"}`
- **PC6**: `{"192.168.196.128", "192.168.194.130"}`
- **PC7**: `{"192.168.195.129", "192.168.194.132"}`

After configuring the IP addresses, you must set up the node key relay routing table. Refer to the `get_next_node_inf()` function in the source code for detailed instructions.

#### Key Simulation Configuration
With the network topology and routing configured, communication between nodes becomes operational. To emulate quantum key distribution (QKD), load the simulated key data files available in our open-source dataset [QNLab-USTC/USTC-QNLab-KMS24-Dataset](https://github.com/QNLab-USTC/USTC-QNLab-KMS24-Dataset). 

Key data files must be named in the format `HostX_HostY.txt`, containing:

For example, a file named `PC1_PC2.txt` might include the following data:
```
1627849623000000, 15
1627849624000000, 10
```
Here, the first column represents the timestamp (in nanoseconds), and the second column indicates the number of key packets transmitted at that time.

- **Timestamps** of key exchanges.
- **Number of transmitted key packets**, simulating the quantum key generation process on the link between HostX and HostY.

For injection, configure the simulated key injection node to read the appropriate key data file.

#### Request Model Configuration
To define a static request input, modify the macro `INIT_REQUEST_LIST` within the source code. Use the following format:
```
{{source_node, destination_node, number_of_packets, transmission_time}}
```
Additionally, for advanced traffic modeling, compile and execute `PPBP_create_file.cpp` to generate request files based on the PPBP traffic model. These files can be subsequently loaded into the program.

### Running the Program
After completing the configurations:

1. Execute the program on the data transmission hosts.
2. Run the program on the simulated injection node.
3. On the simulated injection node terminal, type `begin` to start the experiment.
4. To terminate the experiment, type `end`.

Upon completion, the following outputs will be available on each node:

- **`send_time.csv`**: Records the timestamps of sent packets.
- **`recv_time.csv`**: Records the timestamps of received packets.
- **`HostName.csv`**: Contains information on the request completion queue for the respective node.

Refer to the source code for a detailed explanation of the output formats.

## License
This project is licensed under the **GPL-3.0 license**.

## Contact
For further inquiries or technical support, please contact:
- Email: lijian9@ustc.edu.cn
- Website: [Research Group of Quantum Network, USTC](https://qnlab-ustc.com/)