class colors:
	'''Colors class:
	reset all colors with colors.reset
	two subclasses fg for foreground and bg for background.
	use as colors.subclass.colorname.
	i.e. colors.fg.red or colors.bg.green
	also, the generic bold, disable, underline, reverse, strikethrough,
	and invisible work with the main class
	i.e. colors.bold
	'''
	reset         = '\033[0m'
	end           = '\033[0m'
	bold          = '\033[1m'
	disable       = '\033[2m'
	italic        = '\033[3m'
	url           = '\033[4m'
	blink         = '\033[5m'
	blink2        = '\033[6m'
	selected      = '\033[7m'
	invisible     = '\033[08m'
	strikethrough = '\033[09m'
	
	class fg:
		black  = '\033[30m'
		red    = '\033[31m'
		green  = '\033[32m'
		yellow = '\033[33m'
		blue   = '\033[34m'
		violet = '\033[35m'
		beige  = '\033[36m'
		white  = '\033[37m'

		grey    = '\033[90m'
		red2    = '\033[91m'
		green2  = '\033[92m'
		yellow2 = '\033[93m'
		blue2   = '\033[94m'
		violet2 = '\033[95m'
		beige2  = '\033[96m'
		white2  = '\033[97m'

	class bg:
		blackbg  = '\033[40m'
		redbg    = '\033[41m'
		greenbg  = '\033[42m'
		yellowbg = '\033[43m'
		bluebg   = '\033[44m'
		violetbg = '\033[45m'
		beigebg  = '\033[46m'
		whitebg  = '\033[47m'
		greybg    = '\033[100m'
		redbg2    = '\033[101m'
		greenbg2  = '\033[102m'
		yellowbg2 = '\033[103m'
		bluebg2   = '\033[104m'
		violetbg2 = '\033[105m'
		beigebg2  = '\033[106m'
		whitebg2  = '\033[107m'