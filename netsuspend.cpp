// Network-based timed suspend utility
// Leigh Garbs

#include <algorithm>
#include <csignal>
#include <cstring>
#include <fstream>
#include <linux/if_ether.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

#include "LinuxRawSocket.hpp"
#include "Log.hpp"
#include "ethernet_ii_header.h"
#include "ipv4_header.h"


// Length of the input buffers used during config and default file parsing
#define PARSING_BUFFER_LENGTH 1000


// Filename of the default settings file, typically located in /etc/default
std::string default_filename = "/etc/default/netsuspend";

// Stores a list of all important ports
std::vector<unsigned short> ports;

// Is host computer big endian?
bool is_big_endian;

// Log used to note important events
Log log;


// THESE CONFIGURATION VARIABLES ARE SET BASED ON THE DEFAULT FILE AND/OR
// PROGRAM ARGUMENTS

// Name of the interface on which proxying will take place
std::string interface_name = "eth0";

// Filename of the config file, typically located in /etc
std::string config_filename = "/etc/netsuspend.conf";

// Filename of the log file, typically located in /var/log
std::string log_filename = "/var/log/netsuspend.log";

// Whether or not this process should daemonize
bool daemonize = false;

// How long netsuspend should allow the computer to remain idle before putting
// it to sleep
unsigned int idle_timeout = 15;

// Is the system considered active when a user is logged on?
bool user_check_enabled = false;

// Amount of time (in seconds) to wait between user checks
unsigned int user_check_period = 1;


//=============================================================================
// Performs any clean up that must be done before the program halts
//=============================================================================
void clean_exit(int)
{
  // Log that the service is stopping
  log.write("Service stopping");

  exit(0);
}

//=============================================================================
// Processes program arguments
//=============================================================================
bool process_arguments(int argc, char** argv)
{
  // Loop over all the arguments, and process them
  for (int arg = 1; arg < argc; arg++)
  {
    // Argument -D daemonizes this process
    if (strcmp("-D", argv[arg]) == 0)
    {
      daemonize = true;
    }
    // Argument -c specifies an alternative config file
    else if (strcmp("-c", argv[arg]) == 0 && arg + 1 < argc)
    {
      arg++;

      config_filename = argv[arg];
    }
    // Argument -i specifies an interface to monitor
    else if (strcmp("-i", argv[arg]) == 0 && arg + 1 < argc)
    {
      arg++;

      interface_name = argv[arg];

      // 'all' specified for an interface means monitor every interface; passing
      // an empty string to the socket bind function later (which is what will
      // be done with interface_name) will have this effect
      if (interface_name == "all")
      {
	interface_name = "";
      }
    }
    // Argument -l specifies a file to log to
    else if (strcmp("-l", argv[arg]) == 0 && arg + 1 < argc)
    {
      arg++;

      log_filename = argv[arg];
    }
  }

  // If execution reaches here there was an acceptable set of arguments provided
  return true;
}

//=============================================================================
// Parses configuration file
//=============================================================================
void parse_config_file(const std::string& filename)
{
  // Open the configuration file
  std::fstream config_file(filename.c_str());

  // Read all the lines out of it
  while(!config_file.eof())
  {
    // Read a port number
    unsigned short port;
    config_file >> port;

    // Push the valid port number onto the list if the read was successful
    if (config_file.good())
    {
      ports.push_back(port);
    }

    // Clear any error bits
    config_file.clear();

    // Discard the rest of the line
    char buf = '\0';
    while (!config_file.eof() && buf != '\n')
    {
      config_file.get(buf);
    }
  }
}

//=============================================================================
// Parses default file
//=============================================================================
void parse_default_file(const std::string& filename)
{
  // Open the defaults file
  std::ifstream default_stream(filename.c_str());

  // Initialize some stuff to be used during parsing
  char default_line_buffer[PARSING_BUFFER_LENGTH];
  std::istringstream convert_to_number;

  // Read the entire defaults file
  while(!default_stream.eof())
  {
    // Read a line of the file
    default_stream.getline(default_line_buffer, PARSING_BUFFER_LENGTH);

    // Convert it to a string
    std::string default_line_string = default_line_buffer;

    // Ignore the line if it's a comment
    if (default_line_string[0] == '#')
    {
      continue;
    }

    // Search through the line for a '='
    size_t equal_sign = default_line_string.find('=');

    // If there isn't an equal sign, or the equal sign is at the beginning or
    // end of the buffer, just go to the next line because this line is bad
    if (equal_sign == std::string::npos ||
	equal_sign == 0 ||
	equal_sign == default_line_string.length())
    {
      continue;
    }

    // Pull out the strings on the left and right of the equal sign
    std::string left_side  = default_line_string.substr(0, equal_sign);
    std::string right_side = default_line_string.substr(equal_sign + 1,
							std::string::npos);

    // Clear all convert_to_number flags so it can be used during multiple
    // passes through this loop
    convert_to_number.clear();

    // Now set the appropriate variable based on what was just parsed
    if (left_side == "ETH_INTERFACE")
    {
      interface_name = right_side;

      // 'all' specified for an interface means monitor every interface; passing
      // an empty string to the socket bind function later (which is what will
      // be done with interface_name) will have this effect
      if (interface_name == "all")
      {
	interface_name = "";
      }
    }
    else if (left_side == "CONFIG_FILE")
    {
      config_filename = right_side;
    }
    else if (left_side == "LOG_FILE")
    {
      log_filename = right_side;
    }
    else if (left_side == "DAEMONIZE")
    {
      daemonize = right_side == "yes";
    }
    else if (left_side == "IDLE_TIMEOUT")
    {
      convert_to_number.str(right_side);
      convert_to_number >> idle_timeout;
    }
    else if (left_side == "USER_CHECKING")
    {
      user_check_enabled = right_side == "enabled";
    }
    else if (left_side == "USER_CHECK_PERIOD")
    {
      convert_to_number.str(right_side);
      convert_to_number >> user_check_period;
    }
  }
}

//=============================================================================
// Swaps the two bytes beginning at data
//=============================================================================
void byteswap(char* data)
{
  // Copy the port's two bytes
  char byte1 = *data;
  char byte2 = *(data + 1);

  // Copy the two bytes back in, in reverse order
  memcpy(data,     &byte2, 1);
  memcpy(data + 1, &byte1, 1);
}

//=============================================================================
// Returns a double representation of a timeval timestamp
//=============================================================================
double get_time(const timeval& time)
{
  return time.tv_sec + static_cast<double>(time.tv_usec) / 1e6;
}

//=============================================================================
// Handles Ethernet frames as they are sniffed
//=============================================================================
void handle_frame(char* buffer, timeval& idle_timer)
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
    byteswap((char*)&source_port);
    byteswap((char*)&destination_port);
  }

  // Check both ports against the list of important ports
  if (std::find(ports.begin(), ports.end(), source_port)      == ports.end() &&
      std::find(ports.begin(), ports.end(), destination_port) == ports.end())
  {
    // Traffic is not important, leave
    return;
  }

  // This is an important packet, so reset the idle timer
  gettimeofday(&idle_timer, 0);

  // In order to limit how much time this process takes up, sleep here for a
  // bit.  This helps limit the processing time this process takes when large
  // transfers of important traffic are being done.
  usleep(1000000);
}

//=============================================================================
// Updates current with the new current time, as well as idle_timer if a suspend
// happened
//=============================================================================
void update_times(timeval& current_time, timeval& idle_timer)
{
  // What is the current time?
  timeval new_current_time;
  gettimeofday(&new_current_time, 0);

  // If it been over 5 seconds since the last time the current time was checked,
  // assume the computer this process is running on was suspended and has
  // resumed.  In this case the timer should be reset.
  if (get_time(new_current_time) - get_time(current_time) > 5)
  {
    // Log that this is happening
    log.write("Suspend detected, resetting timer");

    memcpy(&idle_timer, &new_current_time, sizeof(timeval));
  }

  // Update current time
  memcpy(&current_time, &new_current_time, sizeof(timeval));
}

//=============================================================================
// Determines if any users are logged on
//=============================================================================
bool userLoggedOn()
{
  // Run the who command and get a pipe containing its output
  FILE* command_pipe = popen("who | wc -l", "r");

  // Get the command output
  char buffer[PARSING_BUFFER_LENGTH];
  fgets(buffer, PARSING_BUFFER_LENGTH, command_pipe);

  // Close the pipe
  pclose(command_pipe);

  // Convert the command's output into a number
  std::istringstream convert_to_number;
  convert_to_number.str(buffer);

  unsigned int number_of_users;
  convert_to_number >> number_of_users;

  return number_of_users > 0;
}

//=============================================================================
// Program entry point
//=============================================================================
void doUserCheck(timeval& current_time,
		 timeval& idle_timer,
		 timeval& last_user_check)
{
  // If a user is logged on, reset the idle timer
  if (userLoggedOn())
  {
    gettimeofday(&idle_timer, 0);
  }

  // Mark this time as the last time a user check was performed
  gettimeofday(&last_user_check, 0);
}

//=============================================================================
// Program entry point
//=============================================================================
int main(int argc, char** argv)
{
  // Attach clean_exit to the interrupt signal; users can hit Ctrl+c and stop
  // the program
  if (signal(SIGINT, clean_exit) == SIG_ERR)
  {
    fprintf(stderr, "Could not attach SIGINT handler\n");
    return 1;
  }

  // Parse the default file
  parse_default_file(default_filename);

  // Process the arguments
  if (!process_arguments(argc, argv))
  {
    // TODO: show help message here
    exit(0);
  }

  // If this process is to run as a daemon then do it
  if (daemonize)
  {
    if (daemon(0, 0) != 0)
    {
      exit(1);
    }
  }

  // Parse the config file for important ports
  parse_config_file(config_filename);

  // Initialize the logging stream
  std::ofstream log_stream(log_filename.c_str(), std::ofstream::app);
  log.setOutputStream(log_stream);

  // Determine endian-ness of this host
  unsigned short test_var = 0xff00;
  is_big_endian = *(unsigned char*)&test_var > 0;

  // Create the socket to sniff frames on
  LinuxRawSocket sniff_socket;
  sniff_socket.enableBlocking();
  sniff_socket.setBlockingTimeout(1.0);
  sniff_socket.setInputInterface(interface_name);

  // Buffer to sniff data into
  char buffer[ETH_FRAME_LEN];

  // Initialize current time
  timeval current_time;
  gettimeofday(&current_time, 0);

  // This tracks the last time the computer was active.  Subtracting it from
  // current_time yields the amount of idle time
  timeval idle_timer;
  gettimeofday(&idle_timer, 0);

  // This tracks the last time a check for logged-in users was done
  timeval last_user_check;
  gettimeofday(&last_user_check, 0);

  // Note this service is starting
  log.write("Service starting");

  // Start sniffing
  while(true)
  {
    update_times(current_time, idle_timer);

    // Perform a user check, if it is enabled and time to do so
    if (user_check_enabled &&
	get_time(current_time) - get_time(last_user_check) > user_check_period)
    {
      doUserCheck(current_time, idle_timer, last_user_check);
    }

    // Sniff a frame; if nothing was read or an error occurred try again
    if (sniff_socket.read(buffer, ETH_FRAME_LEN) > 0)
    {
      handle_frame(buffer, idle_timer);
    }

    update_times(current_time, idle_timer);
    
    // Determine how long its been since the last important packet was read 
    if ((get_time(current_time) - get_time(idle_timer)) / 60 > idle_timeout)
    {
      // It's been too long since the system received important network traffic,
      // so sleep

      // First, log that we're going to sleep
      log.write("Timer expired, suspending");

      // Actually go to sleep
      system("pm-suspend");

      // At this point the process just woke from sleep

      // Log that we just woke up
      log.write("Resuming from suspend");

      // Reset idle timer.  Suspension counts as an activity.
      gettimeofday(&idle_timer, 0);

      // Dump any data received during the sleep, it's not really that important
      sniff_socket.clearBuffer();
    }
  }

  return 0;
}
