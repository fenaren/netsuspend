#include <algorithm>
#include <cstring>
#include <iostream>
#include <linux/if_ether.h>
#include <stdlib.h>
#include <sys/time.h>
#include <vector>

#include "LinuxRawSocket.hpp"
#include "ethernet_ii_header.h"
#include "ipv4_header.h"

// How long to wait (in minutes) before going to sleep after the last important
// frame was sniffed
#define SLEEP_WAIT 15

void swap16Bit(char* data);
double get_time(const timeval& time);
void handle_frame(char* buffer);

// Stores a list of all important ports
std::vector<unsigned short> ports;

// This tracks how long its been since the last frame with important traffic in
// it was sniffed
timeval last_important_traffic;

// Is host computer big endian?
bool is_big_endian;

int main(int argc, char** argv)
{
  // Create the list of important ports
  ports.push_back(22);   // ssh
  ports.push_back(80);   // http
  ports.push_back(445);  // Windows networking
  ports.push_back(139);  // Windows networking
  ports.push_back(2049); // nfs

  // Create the socket to sniff frames on
  LinuxRawSocket sniff_socket;
  sniff_socket.enableBlocking();
  sniff_socket.setBlockingTimeout(1.0);
  sniff_socket.setInputInterface("eth1");

  // Buffer to sniff data into
  char buffer[ETH_FRAME_LEN];

  // Initialize the time at which the last important traffic was sniffed as now
  gettimeofday(&last_important_traffic, 0);

  // Initialize current time
  timeval current_time;
  gettimeofday(&current_time, 0);

  // Determine endian-ness of this host
  unsigned short test_var = 0xff00;
  is_big_endian = *(unsigned char*)&test_var > 0;

  // Start sniffing
  while(true)
  {
    // Sniff a frame; if nothing was read or an error occurred try again
    if (sniff_socket.read(buffer, ETH_FRAME_LEN) > 0)
    {
      handle_frame(buffer);
    }

    // Update current time
    gettimeofday(&current_time, 0);
    
    // Determine how long its been since the last important packet was read 
    if ((get_time(current_time) - get_time(last_important_traffic)) / 60 > SLEEP_WAIT)
    {
      // It's been too long since the system received important network traffic, sleep
      system("pm-suspend");

      // At this point the process just woke from sleep, reset last important
      // traffic received time to reset the timeout
      gettimeofday(&last_important_traffic, 0);
    }
  }

  return 0;
}

void swap16Bit(char* data)
{
  // Copy the port's two bytes
  char byte1 = *data;
  char byte2 = *(data + 1);

  // Copy the two bytes back in, in reverse order
  memcpy(data,     &byte2, 1);
  memcpy(data + 1, &byte1, 1);
}

double get_time(const timeval& time)
{
  return time.tv_sec + static_cast<double>(time.tv_usec) / 1e6;
}

void handle_frame(char* buffer)
{
  // Assume its an Ethernet II frame
  ethernet_ii_header* eth_header = (ethernet_ii_header*)buffer;

  // Ethertype for IPv4 packets
  char ipv4_type[2];
  ipv4_type[0] = 0x08;
  ipv4_type[1] = 0x00;

  // Ignore any non-IPv4 traffic
  if (memcmp(eth_header->ethertype,
	       (void*)ipv4_type,
	       2) != 0)
  {
    return;
  }

  // Get a handy IPv4-style way to reference the packet
  ipv4_header* ip_header = (ipv4_header*)(buffer + sizeof(ethernet_ii_header));

  // Ignore any non-TCP or UDP traffic
  if (!(*ip_header->protocol == 0x06 || *ip_header->protocol == 0x11))
  {
    return;
  }

  // Figure out how long the header in this IPv4 packet is; we have to do this
  // to know where the payload starts, to know where to pick the ports from

  // The header length in the packet indicates the number of 32-bit words, so
  // the multiply by 4 is necessary to convert to bytes
  unsigned short ip_headerlen = (*(ip_header->version_headerlen) & 0x0f) * 4;

  // Save a pointer to the start of the IPv4 payload
  char* ip_payload = buffer + sizeof(ethernet_ii_header) + ip_headerlen;
  
  // Extract the destination port
  unsigned short source_port = *(unsigned short*)ip_payload;

  // Extract the destination port
  unsigned short destination_port = *(unsigned short*)(ip_payload + 2);

  // If needed, byteswap the ports
  if (!is_big_endian)
  {
    swap16Bit((char*)&source_port);
    swap16Bit((char*)&destination_port);
  }

  // Check both ports against the list of important ports
  if (std::find(ports.begin(), ports.end(), source_port)      == ports.end() &&
      std::find(ports.begin(), ports.end(), destination_port) == ports.end())
  {
    // Traffic is not important, leave
    return;
  }

  //This is an important packet, so mark this moment as the last time an
  //important packet was received
  gettimeofday(&last_important_traffic, 0);
}
