// Network-based timed suspend utility
// Leigh Garbs

#include <algorithm>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <linux/if_ether.h>
#include <map>
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


// Length of the input buffers used during parsing
#define PARSING_BUFFER_LENGTH 1000


enum IdleTimerResetReason
{
  NET_IMPORTANT_TRAFFIC_RECEIVED,
  NET_INTERFACE_BANDWIDTH_THRESHOLD_EXCEEDED,
  DISK_BANDWIDTH_THRESHOLD_EXCEEDED,
  CPU_USAGE_THRESHOLD_EXCEEDED,
  USER_LOGGED_ON,
  IDLE_TIMER_EXPIRED,
  PROGRAM_START
};

// This struct holds all the data we have to track per-disk
struct Disk
{
  unsigned long last_read_time_ms;

  bool last_read_time_good;
};

// This struct holds all the data we have to track per network interface
struct Interface
{
  unsigned long last_bytes_read;
  unsigned long last_bytes_written;

  bool last_bytes_good;
};


// Filename of the config file, typically located in /etc/netsuspend
std::string config_filename = "/etc/netsuspend/config";

// Filename of the file containing what interfaces to monitor for bandwidth;
// this file DOES NOT specify the interfaces on which to snoop for important
// traffic
std::string interfaces_filename = "/etc/netsuspend/interfaces";

// Filename of the file containing what disks to monitor
std::string disks_filename = "/etc/netsuspend/disks";

// Filename of the config file, typically located in /etc
std::string ports_filename = "/etc/netsuspend/ports";

// Filename of the log file, typically located in /var/log
std::string log_filename = "/var/log/netsuspend.log";


// Stores a list of all important ports
std::vector<unsigned short> ports;

// List of interfaces to monitor for bandwidth
std::map<std::string, Interface> interfaces;

// List of disks to monitor for business
std::map<std::string, Disk> disks;

// Is host computer big endian?
bool is_big_endian;

// Log used to note important events
Log log;

// The number of kernel jiffies elapsed 
unsigned int last_jiffy_count = 0;

// The number of idle kernel jiffies elapsed
unsigned int last_idle_jiffy_count = 0;


// Name of the interface on which proxying will take place
std::string interface_name = "eth0";


// Whether or not this process should daemonize
bool daemonize = false;

// How long netsuspend should allow the computer to remain idle before putting
// it to sleep
unsigned int idle_timeout = 15;

// The command to run when idle_timeout elapses
std::string timeout_cmd = "pm-suspend";

// Is the system considered active when a user is logged on?
bool user_check_enabled = false;

// Is the system considered active when the CPU is busy?
bool cpu_check_enabled = false;

// Is the system considered active when disks are busy?
bool disk_check_enabled = false;

// Is the system considered active when network interfaces are busy?
bool net_check_enabled = false;

// Amount of time (in seconds) to wait between CPU checks
unsigned int busy_check_period = 10;

// CPU usage percentage threshold, below which the CPU is considered idle
unsigned int cpu_usage_threshold = 5;

// Disk usage percentage threshold, below which the disk is considered idle
unsigned int disk_usage_threshold = 5;

// Network usage threshold, below which the disk is considered idle.  Given in
// bits per second
unsigned int net_usage_threshold = 1000000;

// Is verbose logging enabled?
bool verbose_logging_enabled = false;

// Why was the last idle timer reset done?
IdleTimerResetReason last_idle_timer_reset_reason = PROGRAM_START;


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
    // Argument --config specifies an alternative config file
    else if (strcmp("--config", argv[arg]) == 0 && arg + 1 < argc)
    {
      arg++;

      config_filename = argv[arg];
    }
    // Argument --ports specifies an alternative ports file
    else if (strcmp("--ports", argv[arg]) == 0 && arg + 1 < argc)
    {
      arg++;

      ports_filename = argv[arg];
    }
    // Argument --disks specifies an alternative disks file
    else if (strcmp("--disks", argv[arg]) == 0 && arg + 1 < argc)
    {
      arg++;

      disks_filename = argv[arg];
    }
    // Argument --interfaces specifies an alternative interfaces file
    else if (strcmp("--interfaces", argv[arg]) == 0 && arg + 1 < argc)
    {
      arg++;

      interfaces_filename = argv[arg];
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
    // Argument --log specifies a file to log to
    else if (strcmp("--log", argv[arg]) == 0 && arg + 1 < argc)
    {
      arg++;

      log_filename = argv[arg];
    }
    // Argument --verbose-log means to log more information
    else if (strcmp("--verbose-log", argv[arg]) == 0)
    {
      verbose_logging_enabled = true;
    }
  }

  // If execution reaches here there was an acceptable set of arguments provided
  return true;
}

//=============================================================================
// Parses configuration file
//=============================================================================
void parse_ports_file(const std::string& filename)
{
  // Open the ports file
  std::fstream ports_file(filename.c_str());

  // Read all the lines out of it
  while(!ports_file.eof())
  {
    // Read a port number
    unsigned short port;
    ports_file >> port;

    // Push the valid port number onto the list if the read was successful
    if (ports_file.good())
    {
      ports.push_back(port);
    }

    // Clear any error bits
    ports_file.clear();

    // Discard the rest of the line
    char buf = '\0';
    while (!ports_file.eof() && buf != '\n')
    {
      ports_file.get(buf);
    }
  }
}

//=============================================================================
// Parses config file
//=============================================================================
void parse_config_file(const std::string& filename)
{
  // Open the config file
  std::ifstream config_stream(filename.c_str());

  // Initialize some stuff to be used during parsing
  char config_line_buffer[PARSING_BUFFER_LENGTH];
  std::istringstream convert_to_number;

  // Read the entire config file
  while(!config_stream.eof())
  {
    // Read a line of the file
    config_stream.getline(config_line_buffer, PARSING_BUFFER_LENGTH);

    // Convert it to a string
    std::string config_line_string = config_line_buffer;

    // Ignore the line if it's a comment
    if (config_line_string[0] == '#')
    {
      continue;
    }

    // Search through the line for a '='
    size_t equal_sign = config_line_string.find('=');

    // If there isn't an equal sign, or the equal sign is at the beginning or
    // end of the buffer, just go to the next line because this line is bad
    if (equal_sign == std::string::npos ||
        equal_sign == 0 ||
        equal_sign == config_line_string.length())
    {
      continue;
    }

    // Pull out the strings on the left and right of the equal sign
    std::string left_side  = config_line_string.substr(0, equal_sign);
    std::string right_side = config_line_string.substr(equal_sign + 1,
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
    else if (left_side == "TIMEOUT_CMD")
    {
      timeout_cmd = right_side;
    }
    else if (left_side == "USER_CHECKING")
    {
      user_check_enabled = right_side == "enabled";
    }
    else if (left_side == "CPU_CHECKING")
    {
      cpu_check_enabled = right_side == "enabled";
    }
    else if (left_side == "DISK_CHECKING")
    {
      disk_check_enabled = right_side == "enabled";
    }
    else if (left_side == "NET_CHECKING")
    {
      net_check_enabled = right_side == "enabled";
    }
    else if (left_side == "BUSY_CHECK_PERIOD")
    {
      convert_to_number.str(right_side);
      convert_to_number >> busy_check_period;
    }
    else if (left_side == "CPU_USAGE_THRESHOLD")
    {
      convert_to_number.str(right_side);
      convert_to_number >> cpu_usage_threshold;
    }
    else if (left_side == "DISK_USAGE_THRESHOLD")
    {
      convert_to_number.str(right_side);
      convert_to_number >> disk_usage_threshold;
    }
    else if (left_side == "NET_USAGE_THRESHOLD")
    {
      convert_to_number.str(right_side);
      convert_to_number >> net_usage_threshold;
    }
  }
}

//=============================================================================
// Parses interfaces file
//=============================================================================
void parse_interfaces_file(const std::string& filename)
{
  std::ifstream interfaces_stream(filename.c_str());

  // Read the entire interfaces file
  while(!interfaces_stream.eof())
  {
    std::string interface;
    interfaces_stream >> interface;

    // Initialize an Interface structure for this interface
    Interface interfaceparams;
    interfaceparams.last_bytes_read = 0;
    interfaceparams.last_bytes_written = 0;
    interfaceparams.last_bytes_good = false;

    interfaces[interface] = interfaceparams;
  }
}

//=============================================================================
// Parses disks file
//=============================================================================
void parse_disks_file(const std::string& filename)
{
  std::ifstream disks_stream(filename.c_str());

  // Read the entire interfaces file
  while(!disks_stream.eof())
  {
    std::string disk;
    disks_stream >> disk;

    // Initialize a Disk structure for this disk
    Disk diskparams;
    diskparams.last_read_time_ms = 0;
    diskparams.last_read_time_good = false;

    disks[disk] = diskparams;
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
  if (memcmp(eth_header->ethertype, (void*)ipv4_type, 2) != 0)
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

  last_idle_timer_reset_reason = NET_IMPORTANT_TRAFFIC_RECEIVED;

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
bool user_logged_on()
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
// Resets the idle timer if a user is logged in
//=============================================================================
void do_user_check(timeval& idle_timer)
{
  // If a user is logged on, reset the idle timer
  if (user_logged_on())
  {
    gettimeofday(&idle_timer, 0);
  }
}

//=============================================================================
// Determines if the CPU is busy
//=============================================================================
bool cpu_is_busy()
{
  // Open /proc/stat, this is where the CPU stats are
  std::ifstream is("/proc/stat", std::ofstream::in);

  // All the aggregate CPU stats are on the first line, the rest will be ignored

  // Read and discard the 'cpu' at the beginning
  std::string not_used;
  is >> not_used;

  // Will be filled in by the loop below
  unsigned int jiffy_count = 0;
  unsigned int idle_jiffy_count = 0;

  // Get the first three jiffy counts
  unsigned int temp;
  for (int i = 0; i < 3; i++)
  {
    is >> temp;
    jiffy_count += temp;
  }

  // Read the idle jiffy count
  is >> idle_jiffy_count;
  jiffy_count += idle_jiffy_count;

  // Get the rest of the jiffy counts
  for (int i = 0; i < 6; i++)
  {
    is >> temp;
    jiffy_count += temp;
  }

  // Close /proc/stat
  is.close();

  // Now compare the current jiffy counts with the last recorded jiffy counts to
  // determine idleness
  unsigned int idle_jiffies_elapsed = idle_jiffy_count - last_idle_jiffy_count;
  unsigned int jiffies_elapsed = jiffy_count - last_jiffy_count;

  // Compute the usage percentage
  double usage_pct =
    (1 - ((double)idle_jiffies_elapsed / (double)jiffies_elapsed)) * 100;

  // Save the jiffy counts that were just calculated
  last_idle_jiffy_count = idle_jiffy_count;
  last_jiffy_count = jiffy_count;

  return usage_pct > cpu_usage_threshold;
}

//=============================================================================
// Resets the idle timer if the CPU is busy
//=============================================================================
void do_cpu_check(timeval& idle_timer)
{
  // If the CPU is busy, reset the timer
  if (cpu_is_busy())
  {
    gettimeofday(&idle_timer, 0);

    last_idle_timer_reset_reason = CPU_USAGE_THRESHOLD_EXCEEDED;
  }
}

//=============================================================================
// Determines if the disks are busy
//=============================================================================
bool disk_is_busy()
{
  // Open /proc/diskstats, this is the file we're going to check
  std::ifstream diskstats_stream("/proc/diskstats");

  // Initialize some stuff to be used during parsing
  char diskstats_line_buffer[PARSING_BUFFER_LENGTH];

  // Will be set true if a disk is busy
  bool is_busy = false;

  // Read the entire config file
  while(!diskstats_stream.eof())
  {
    // Read a line of the file
    diskstats_stream.getline(diskstats_line_buffer, PARSING_BUFFER_LENGTH);

    // Does this line correspond to any of the disks we're supposed to be
    // monitoring?

    // First thing to do is compare the disk on this line to all the disks we're
    // supposed to monitor
    std::istringstream diskstats_line_stream(diskstats_line_buffer);
    std::string disk;
    diskstats_line_stream >> disk >> disk >> disk;

    // If disk is empty then we're probably reading the last empty line.  At any
    // rate don't consider this line
    if (disk.empty())
    {
      continue;
    }

    for (std::map<std::string, Disk>::iterator i = disks.begin();
         i != disks.end();
         i++)
    {
      // See if this disk is one we're supposed to monitor
      if (i->first == disk)
      {
        // Read out the 10th field
        std::string read_time_ms_str;
        for (unsigned int j = 0; j < 10; j++)
        {
          diskstats_line_stream >> read_time_ms_str;
        }

        std::istringstream convert_to_number(read_time_ms_str);
        unsigned long read_time_ms;
        convert_to_number >> read_time_ms;

        // Only check disk usage time if the counter hasn't overflowed
        if (read_time_ms >= i->second.last_read_time_ms)
        {
          // What's the time disk usage pct?
          double usage_pct =
            static_cast<double>(read_time_ms - i->second.last_read_time_ms) /
            1000.0 /
            static_cast<double>(busy_check_period) *
            100.0;

          // Is this disk busy?
          if (i->second.last_read_time_good && usage_pct > disk_usage_threshold)
          {
            is_busy = true;
          }
        }

        // Set things up to work during the next check
        i->second.last_read_time_ms = read_time_ms;
        i->second.last_read_time_good = true;
      }
    }
  }

  return is_busy;
}

//=============================================================================
// Resets the idle timer if the disks are busy
//=============================================================================
void do_disk_check(timeval& idle_timer)
{
  // If the disks are busy, reset the timer
  if (disk_is_busy())
  {
    gettimeofday(&idle_timer, 0);

    last_idle_timer_reset_reason = DISK_BANDWIDTH_THRESHOLD_EXCEEDED;
  }
}

//=============================================================================
// Determines if the network is busy
//=============================================================================
bool net_is_busy()
{
  // Open /proc/net/dev, this is the file we're going to check
  std::ifstream netstats_stream("/proc/net/dev");

  // Initialize some stuff to be used during parsing
  char netstats_line_buffer[PARSING_BUFFER_LENGTH];

  // Will be set true if a network interface is busy
  bool is_busy = false;

  // The first two lines of this file aren't useful so read and discard them
  netstats_stream.getline(netstats_line_buffer, PARSING_BUFFER_LENGTH);
  netstats_stream.getline(netstats_line_buffer, PARSING_BUFFER_LENGTH);

  // Read the entire file
  while(!netstats_stream.eof())
  {
    // Read a line of the file
    netstats_stream.getline(netstats_line_buffer, PARSING_BUFFER_LENGTH);

    // Does this line correspond to any of the interfaces we're supposed to be
    // monitoring?

    // First thing to do is compare the interface on this line to all the disks
    // we're supposed to monitor
    std::istringstream netstats_line_stream(netstats_line_buffer);
    std::string interface;
    netstats_line_stream >> interface;
    if (interface.empty())
    {
      continue;
    }

    // Get rid of the colon on the end
    interface = interface.substr(0, interface.length() - 1);

    // Does this interface match any of the interfaces we're supposed to be
    // watching for?
    std::map<std::string, Interface>::iterator i = interfaces.find(interface);
    if (i != interfaces.end())
    {
      unsigned long bytes_read = 0;
      unsigned long bytes_written= 0;

      netstats_line_stream >> bytes_read;

      // Discard the next 7 fields and keep the 8th, that's the # of bytes
      // written
      for (unsigned int j = 0; j < 8; j++)
      {
        netstats_line_stream >> bytes_written;
      }

      // Come up with the average number of bytes written per second over the
      // last "busy_check_period" seconds
      double avg_bytes_read =
        static_cast<double>(bytes_read - i->second.last_bytes_read) /
        static_cast<double>(busy_check_period);
      double avg_bytes_written =
        static_cast<double>(bytes_written - i->second.last_bytes_written) /
        static_cast<double>(busy_check_period);

      // If we've read or written more than the threshold and we have a good
      // last value to base this calculation on, then the network is busy
      if (i->second.last_bytes_good &&
          (avg_bytes_read > net_usage_threshold ||
           avg_bytes_written > net_usage_threshold))
      {
        is_busy = true;
      }

      // Save state for the next iteration
      i->second.last_bytes_read = bytes_read;
      i->second.last_bytes_written = bytes_written;
      i->second.last_bytes_good = true;
    }
  }

  return is_busy;
}

//=============================================================================
// Resets the idle timer if the network is busy
//=============================================================================
void do_net_check(timeval& idle_timer)
{
  // If the network is busy, reset the timer
  if (net_is_busy())
  {
    gettimeofday(&idle_timer, 0);

    last_idle_timer_reset_reason = NET_INTERFACE_BANDWIDTH_THRESHOLD_EXCEEDED;
  }
}

//=============================================================================
// Program entry point
//=============================================================================
int main(int argc, char** argv)
{
  // Attach clean_exit to the interrupt and kill signals; users can hit Ctrl+c and
  // stop the program
  if (signal(SIGINT, clean_exit) == SIG_ERR)
  {
    fprintf(stderr, "Could not attach SIGINT handler\n");
    return 1;
  }

  if (signal(SIGTERM, clean_exit) == SIG_ERR)
  {
    fprintf(stderr, "Could not attach SIGTERM handler\n");
    return 1;
  }

  // Parse the config file
  parse_config_file(config_filename);

  // Process the arguments
  if (!process_arguments(argc, argv))
  {
    // TODO: show help message here
    exit(0);
  }

  // Parse the config file for important ports
  parse_ports_file(ports_filename);

  // Parse the config file for important ports
  parse_interfaces_file(interfaces_filename);

  // Parse the config file for important ports
  parse_disks_file(disks_filename);


  // If this process is to run as a daemon then do it
  if (daemonize)
  {
    if (daemon(0, 0) != 0)
    {
      exit(1);
    }
  }

  // Initialize the logging stream
  std::ofstream log_stream(log_filename.c_str(), std::ofstream::app);
  log.setOutputStream(log_stream);
  log.flushAfterWrite(true);
  log.useLocalTime();

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
  timeval last_busy_check;
  gettimeofday(&last_busy_check, 0);

  // This tracks the last time a verbose log entry was written
  timeval last_verbose_log_entry;
  gettimeofday(&last_verbose_log_entry, 0);


  // Note this service is starting
  log.write("Service starting");

  // Start sniffing
  while(true)
  {
    update_times(current_time, idle_timer);

    // Perform busy checks if it's time to do so
    if (get_time(current_time) - get_time(last_busy_check) > busy_check_period)
    {
      // Perform a user check if enabled
      if (user_check_enabled)
      {
        do_user_check(idle_timer);
      }

      // Perform a CPU check if enabled
      if (cpu_check_enabled)
      {
        do_cpu_check(idle_timer);
      }

      // Perform a disk check if enabled
      if (disk_check_enabled)
      {
        do_disk_check(idle_timer);
      }

      // Perform a network check if enabled
      if (net_check_enabled)
      {
        do_net_check(idle_timer);
      }

      // Mark this time as the last time a busy check was performed
      gettimeofday(&last_busy_check, 0);
    }

    // Sniff a frame; if nothing was read or an error occurred try again
    if (sniff_socket.read(buffer, ETH_FRAME_LEN) > 0)
    {
      handle_frame(buffer, idle_timer);
    }

    update_times(current_time, idle_timer);

    // If verbose logging is enabled here is where we see if it's time to write
    // averbose log entry
    if (verbose_logging_enabled)
    {
      if (get_time(current_time) - get_time(last_verbose_log_entry) > 30)
      {
        // How long have we been idle?
        double idle_time = get_time(current_time) - get_time(idle_timer);

        // Build the verbose log entry
        std::stringstream to_string;
        to_string.precision(1);
        to_string << std::fixed << "Idle timer " << idle_time / 60.0 << " / "
                  << idle_timeout << " min, last reset for ";

        switch(last_idle_timer_reset_reason)
        {
        case NET_IMPORTANT_TRAFFIC_RECEIVED:
          to_string << "important network traffic";
          break;

        case NET_INTERFACE_BANDWIDTH_THRESHOLD_EXCEEDED:
          to_string << "network interface bandwidth threshold exceeded";
          break;

        case DISK_BANDWIDTH_THRESHOLD_EXCEEDED:
          to_string << "disk bandwidth threshold exceeded";
          break;

        case CPU_USAGE_THRESHOLD_EXCEEDED:
          to_string << "CPU usage threshold exceeded";
          break;

        case USER_LOGGED_ON:
          to_string << "user logged on";
          break;

        case PROGRAM_START:
          to_string << "program start";
          break;

        case IDLE_TIMER_EXPIRED:
          to_string << "idle timer expiration";
          break;

        default:
          to_string << "an unknown reason";
          break;
        }

        // Write the verbose log entry
        log.write(to_string.str());

        // Reset the verbose log entry timer
        gettimeofday(&last_verbose_log_entry, 0);
      }
    }

    // Determine how long its been since the last important packet was read
    if ((get_time(current_time) - get_time(idle_timer)) / 60 > idle_timeout)
    {
      // It's been too long since the system received important network traffic,
      // so sleep

      // First, log that we're going to sleep
      log.write("Timer expired, running " + timeout_cmd);

      // Actually go to sleep
      system(timeout_cmd.c_str());

      // At this point the process just woke from sleep

      // Log that we just woke up
      log.write("Returning from " + timeout_cmd);

      // Reset idle timer.  Suspension counts as an activity.
      gettimeofday(&idle_timer, 0);
      last_idle_timer_reset_reason = IDLE_TIMER_EXPIRED;

      // Dump any data received during the sleep, it's not really that important
      sniff_socket.clearBuffer();
    }
  }

  return 0;
}
