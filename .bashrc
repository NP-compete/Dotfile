# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
#force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	# We have color support; assume it's compliant with Ecma-48
	# (ISO/IEC-6429). (Lack of such support is extremely rare, and such
	# a case would tend to support setf rather than setaf.)
	color_prompt=yes
    else
	color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# colored GCC warnings and errors
#export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Add an "alert" alias for long running commands.  Use like so:
#   sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi

export CATALINA_HOME=/opt/tomcat
export CLASSPATH=$CLASSPATH:/opt/tomcat/lib/servlet-api.jar
export CLASSPATH=$CLASSPATH:/usr/share/java/mysql-connector-java.jar
export CLASSPATH=$CLASSPATH:.


#export opentabs=$(find ~/.mozilla/firefox*/*.default/sessionstore-backups/recovery.jsonlz4);

#alarm() { cd /opt/alarm/; echo "12345"|sudo -S ./InsaneAlarm &; cd /home/soham/; }

# remove duplicate path entries
export PATH=$(echo $PATH | awk -F: '
{ for (i = 1; i <= NF; i++) arr[$i]; }
END { for (i in arr) printf "%s:" , i; printf "\n"; } ')

# autocomplete ssh commands
complete -W "$(echo `cat ~/.bash_history | egrep '^ssh ' | sort | uniq | sed 's/^ssh //'`;)" ssh




##################################################
# Automatically clean up all temporary files in	 #
# $HOME directory				 #
##################################################

#find "$HOME" -type f \( -name "*~" -or -name ".*~" -or -name "*.old" -or -name "*.bak" -or -name "*.OLD" -or -name "*.BAK" \)|xargs -I{} bash -c "rm -rf \"{}\""


##################################################
# Stop Flash from tracking everything you do.	 #
##################################################

###### Brute force way to block all LSO cookies on Linux system with non-free Flash browser plugin
# for A in ~/.adobe ~/.macromedia ; do ( [ -d $A ] && rm -rf $A ; ln -s -f /dev/null $A ) ; done
for A in ~/.macromedia ; do ( [ -d $A ] && rm -rf $A ; ln -s -f /dev/null $A ) ; done


##################################################
# To enable tab-completion with sudo		 #
##################################################

###### alternatively, install bash-completion, which does this too
# complete -cf sudo



##################################################
# Completion functions (only since Bash-2.04)	 #
##################################################

###### avoid tilde expansion from the bash_completion script
function _expand()
{
    [ "$cur" != "${cur%\\}" ] && cur="$cur\\";
    if [[ "$cur" == \~*/* ]]; then
        #eval cur=$cur;
		:;
    else
        if [[ "$cur" == \~* ]]; then
            cur=${cur#\~};
            COMPREPLY=($( compgen -P '~' -u $cur ));
            return ${#COMPREPLY[@]};
        fi;
    fi
}



function _get_longopts()
{
    # $1 --help | sed  -e '/--/!d' -e 's/.*--\([^[:space:].,]*\).*/--\1/'| \
# grep ^"$2" |sort -u ;
    $1 --help | grep -o -e "--[^[:space:].,]*" | grep -e "$2" |sort -u
}



function _killall()
{
    local cur prev
    COMPREPLY=()
    cur=${COMP_WORDS[COMP_CWORD]}
    # get a list of processes (the first sed evaluation
    # takes care of swapped out processes, the second
    # takes care of getting the basename of the process)
    COMPREPLY=( $( /usr/bin/ps -u $USER -o comm  | \
        sed -e '1,1d' -e 's#[]\[]##g' -e 's#^.*/##'| \
        awk '{if ($0 ~ /^'$cur'/) print $0}' ))
    return 0
}
complete -F _killall killall killps



function _longopts()
{
    local cur
    cur=${COMP_WORDS[COMP_CWORD]}
    case "${cur:-*}" in
       -*)      ;;
        *)      return ;;
    esac
    case "$1" in
      \~*)      eval cmd="$1" ;;
        *)      cmd="$1" ;;
    esac
    COMPREPLY=( $(_get_longopts ${1} ${cur} ) )
}
complete  -o default -F _longopts configure bash
complete  -o default -F _longopts wget id info a2ps ls recode



function _make()
{
    local mdef makef makef_dir="." makef_inc gcmd cur prev i;
    COMPREPLY=();
    cur=${COMP_WORDS[COMP_CWORD]};
    prev=${COMP_WORDS[COMP_CWORD-1]};
    case "$prev" in
        -*f)
            COMPREPLY=($(compgen -f $cur ));
            return 0
        ;;
    esac;
    case "$cur" in
        -*)
            COMPREPLY=($(_get_longopts $1 $cur ));
            return 0
        ;;
    esac;
    # make reads `GNUmakefile', then `makefile', then `Makefile'
    if [ -f ${makef_dir}/GNUmakefile ]; then
        makef=${makef_dir}/GNUmakefile
    elif [ -f ${makef_dir}/makefile ]; then
        makef=${makef_dir}/makefile
    elif [ -f ${makef_dir}/Makefile ]; then
        makef=${makef_dir}/Makefile
    else
        makef=${makef_dir}/*.mk        # Local convention.
    fi
    # Before we scan for targets, see if a Makefile name was
    # specified with -f ...
    for (( i=0; i < ${#COMP_WORDS[@]}; i++ )); do
        if [[ ${COMP_WORDS[i]} == -f ]]; then
           # eval for tilde expansion
           eval makef=${COMP_WORDS[i+1]}
           break
        fi
    done
    [ ! -f $makef ] && return 0
    # deal with included Makefiles
    makef_inc=$( grep -E '^-?include' $makef | \
    sed -e "s,^.* ,"$makef_dir"/," )
    for file in $makef_inc; do
        [ -f $file ] && makef="$makef $file"
    done
    # If we have a partial word to complete, restrict completions to
    # matches of that word.
    if [ -n "$cur" ]; then gcmd='grep "^$cur"' ; else gcmd=cat ; fi
    COMPREPLY=( $( awk -F':' '/^[a-zA-Z0-9][^$#\/\t=]*:([^=]|$)/ \
                                {split($1,A,/ /);for(i in A)print A[i]}' \
                                $makef 2>/dev/null | eval $gcmd  ))
}
complete -F _make -X '+($*|*.[cho])' make gmake pmake\



###### A meta-command completion function for commands like sudo(8), which need to
# first complete on a command, then complete according to that command's own
# completion definition - currently not quite foolproof,
# but still quite useful (By Ian McDonald, modified by me).
function _meta_comp()
{
    local cur func cline cspec
    COMPREPLY=()
    cur=${COMP_WORDS[COMP_CWORD]}
    cmdline=${COMP_WORDS[@]}
    if [ $COMP_CWORD = 1 ]; then
         COMPREPLY=( $( compgen -c $cur ) )
    else
        cmd=${COMP_WORDS[1]}            # Find command.
        cspec=$( complete -p ${cmd} )   # Find spec of that command.
        # COMP_CWORD and COMP_WORDS() are not read-only,
        # so we can set them before handing off to regular
        # completion routine:
        # Get current command line minus initial command,
        cline="${COMP_LINE#$1 }"
        # split current command line tokens into array,
        COMP_WORDS=( $cline )
        # set current token number to 1 less than now.
        COMP_CWORD=$(( $COMP_CWORD - 1 ))
        # If current arg is empty, add it to COMP_WORDS array
        # (otherwise that information will be lost).
        if [ -z $cur ]; then COMP_WORDS[COMP_CWORD]=""  ; fi
        if [ "${cspec%%-F *}" != "${cspec}" ]; then
      # if -F then get function:
            func=${cspec#*-F }
            func=${func%% *}
            eval $func $cline   # Evaluate it.
        else
            func=$( echo $cspec | sed -e 's/^complete//' -e 's/[^ ]*$//' )
            COMPREPLY=( $( eval compgen $func $cur ) )
        fi
    fi
}
complete -o default -F _meta_comp nohup \
eval exec trace truss strace sotruss gdb
complete -o default -F _meta_comp command type which man nice time



function _tar()
{
    local cur ext regex tar untar
    COMPREPLY=()
    cur=${COMP_WORDS[COMP_CWORD]}
    # If we want an option, return the possible long options.
    case "$cur" in
        -*)     COMPREPLY=( $(_get_longopts $1 $cur ) ); return 0;;
    esac
    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=( $( compgen -W 'c t x u r d A' -- $cur ) )
        return 0
    fi
    case "${COMP_WORDS[1]}" in
        ?(-)c*f)
            COMPREPLY=( $( compgen -f $cur ) )
            return 0
            ;;
            +([^Izjy])f)
            ext='tar'
            regex=$ext
            ;;
        *z*f)
            ext='tar.gz'
            regex='t\(ar\.\)\(gz\|Z\)'
            ;;
        *[Ijy]*f)
            ext='t?(ar.)bz?(2)'
            regex='t\(ar\.\)bz2\?'
            ;;
        *)
            COMPREPLY=( $( compgen -f $cur ) )
            return 0
            ;;
    esac
    if [[ "$COMP_LINE" == tar*.$ext' '* ]]; then
        # Complete on files in tar file.
        #
        # Get name of tar file from command line.
        tar=$( echo "$COMP_LINE" | \
               sed -e 's|^.* \([^ ]*'$regex'\) .*$|\1|' )
        # Devise how to untar and list it.
        untar=t${COMP_WORDS[1]//[^Izjyf]/}
        COMPREPLY=( $( compgen -W "$( echo $( tar $untar $tar \
                    2>/dev/null ) )" -- "$cur" ) )
        return 0

    else
        # File completion on relevant files.
        COMPREPLY=( $( compgen -G $cur\*.$ext ) )
    fi
    return 0
}
complete -F _tar -o default tar



##################################################
##################################################
##################################################


##################################################
# Add a function you've defined to .bashrc	 #
##################################################

function addfunction() { declare -f $1 >> ~/.bashrc ; }



##################################################
# OpenPGP/GPG pubkeys stuff (for Launchpad / etc.#
##################################################

###### add keys
alias addkey='sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys'



###### autograb missing keys
alias autokey='sudo apt-get update 2> /tmp/keymissing; for key in $(grep "NO_PUBKEY" /tmp/keymissing |sed "s/.*NO_PUBKEY //"); do echo -e "\nProcessing key: $key"; gpg --keyserver pool.sks-keyservers.net --recv $key && gpg --export --armor $key | sudo apt-key add -; done'



###### create mykeys for use on Launchpad / etc.
alias createmykeys='gpg --gen-key'



###### show single repo key info using keyid found in 'sudo apt-key list'
alias exportkey='sudo apt-key export'



###### exports all repo keys info into single 'repokeys.txt' document
alias exportkeys='sudo apt-key exportall > repokeys.txt'



###### to export public OpenPGP keys to a file for safe keeping and potential restoration
alias exportmykeys='exportmykeys_private && exportmykeys_public'



###### to export private OpenPGP keys to a file for safe keeping and potential restoration
# using 'mykeys', put the appropriate GPG key after you type this function
function exportmykeys_private()
{
gpg --list-secret-keys
echo -n "Please enter the appropriate private key...
Look for the line that starts something like "sec 1024D/".
The part after the 1024D is the key_id.
...like this: '2942FE31'...

"
read MYKEYPRIV
gpg -ao Private_Keys-private.key --export-secret-keys "$MYKEYPRIV"
echo -n "All done."
}



###### to export public OpenPGP keys to a file for safe keeping and potential restoration
# using 'mykeys', put the appropriate GPG key after you type this function
function exportmykeys_public()
{
gpg --list-keys
echo -n "Please enter the appropriate public key...
Look for line that starts something like "pub 1024D/".
The part after the 1024D is the public key_id.
...like this: '2942FE31'...

"
read MYKEYPUB
gpg -ao Public_Keys-public.key --export "$MYKEYPUB"
echo -n "All done."
}



###### to get the new key fingerprint for use in the appropriate section on Launchpad.net to start verification process
alias fingerprintmykeys='gpg --fingerprint'



###### to automatically get all pubkeys (Launchpad PPA ones and others)
# requires: sudo apt-get install launchpad-getkeys
alias getkeys='sudo launchpad-getkeys'



###### to get a list of your public and private OpenPGP/GPG pubkeys
alias mykeys='gpg --list-keys && gpg --list-secret-keys'



###### publish newly-created mykeys for use on Launchpad / etc.
alias publishmykeys='gpg --keyserver hkp://keyserver.ubuntu.com --send-keys'



###### to restore your public and private OpenPGP keys
# from Public_Key-public.key and Private_Keys-private.key files:
function restoremykeys()
{
echo -n "Please enter the full path to Public keys (spaces are fine)...

Example: '/home/(your username)/Public_Key-public.key'...

"
read MYKEYS_PUBLIC_LOCATION
gpg --import "$MYKEYS_PUBLIC_LOCATION"
echo -n "Please enter the full path to Private keys (spaces are fine)...

Example: '/home/(your username)/Private_Keys-private.key'...

"
read MYKEYS_PRIVATE_LOCATION
gpg --import "$MYKEYS_PRIVATE_LOCATION"
echo -n "All done."
}



###### to setup new public and private OpenPGP keys
function setupmykeys()
{
# Generate new key
gpg --gen-key
# Publish new key to Ubuntu keyserver
gpg --keyserver hkp://keyserver.ubuntu.com --send-keys
# Import an OpenPGP key
gpg --fingerprint
# Verify new key
read -sn 1 -p "Before you continue, you must enter the fingerprint
in the appropriate place in your Launchpad PPA on their website...

Once you have successfully inputed it, wait for your email before
you press any key to continue...

"
gedit $HOME/file.txt
read -sn 1 -p "Once you have received your email from Launchpad to
verify your new key, copy and paste the email message received upon
import of OpenPGP key from "-----BEGIN PGP MESSAGE-----" till
"-----END PGP MESSAGE-----" to the 'file.txt' in your home folder
that was just opened for you

Once you have successfully copied and pasted it, save it and
press any key to continue...

"
gpg -d $HOME/file.txt
echo -n "All done."
}



###### shows list of repository keys
alias showkeys='sudo apt-key list'


##################################################
# Network information and IP address stuff	 #
##################################################


###### check if a remote port is up using dnstools.com
# (i.e. from behind a firewall/proxy)
function cpo() { [[ $# -lt 2 ]] && echo 'need IP and port' && return 2; [[ `wget -q "http://dnstools.com/?count=3&checkp=on&portNum=$2&target=$1&submit=Go\!" -O - |grep -ic "Connected successfully to port $2"` -gt 0 ]] && echo OPEN || echo CLOSED; }



###### find an unused unprivileged TCP port
function findtcp()
{
(netstat  -atn | awk '{printf "%s\n%s\n", $4, $4}' | grep -oE '[0-9]*$'; seq 32768 61000) | sort -n | uniq -u | head -n 1
}


###### display private IP
function ippriv()
{
    ifconfig wlp2s0 | grep inet | awk '{print $2}' | head -1
}



###### find the IP addresses that are currently online in your network
function localIps()
{
for i in {1..254}; do
	x=`ping -c1 -w1 10.10.10.$i | grep "%" | cut -d"," -f3 | cut -d"%" -f1 | tr '\n' ' ' | sed 's/ //g'`
	if [ "$x" == "0" ]; then
		echo "10.10.10.$i"
	fi
done
}


###### show ip
# copyright 2007 - 2010 Christopher Bratusek
function show_ip()
{
	wget -q -O - http://showip.spamt.net/
}


###### show Url information
# Usage:	url-info "ur"
# This script is part of nixCraft shell script collection (NSSC)
# Visit http://bash.cyberciti.biz/ for more information.
# Modified by Silviu Silaghi (http://docs.opensourcesolutions.ro) to handle
# more ip adresses on the domains on which this is available (eg google.com or yahoo.com)
# Last updated on Sep/06/2010
function url-info()
{
doms=$@
if [ $# -eq 0 ]; then
echo -e "No domain given\nTry $0 domain.com domain2.org anyotherdomain.net"
fi
for i in $doms; do
_ip=$(host $i|grep 'has address'|awk {'print $4'})
if [ "$_ip" == "" ]; then
echo -e "\nERROR: $i DNS error or not a valid domain\n"
continue
fi
ip=`echo ${_ip[*]}|tr " " "|"`
echo -e "\nInformation for domain: $i [ $ip ]\nQuerying individual IPs"
 for j in ${_ip[*]}; do
echo -e "\n$j results:"
whois $j |egrep -w 'OrgName:|City:|Country:|OriginAS:|NetRange:'
done
done
}



###### cleanly list available wireless networks (using iwlist)
function wscan()
{
iwlist wlp2s0	 scan | sed -ne 's#^[[:space:]]*\(Quality=\|Encryption key:\|ESSID:\)#\1#p' -e 's#^[[:space:]]*\(Mode:.*\)$#\1\n#p'
}



##################################################
# Show all strings (ASCII & Unicode) in a file	 #
##################################################

function allStrings() { cat "$1" | tr -d "\0" | strings ; }



##################################################
# Find all videos under current directory using	 #
# MIME a.k.a not using extension		 #
##################################################

function allVideos() { find ./ -type f -print0 | xargs -0 file -iNf - | grep ": video/" | cut -d: -f1 ; }



##################################################
# Miscellaneous Fun				 #
##################################################

###### fake error string
function error()
{
while true; do awk '{ print ; system("let R=$RANDOM%10; sleep $R") }' compiler.log; done
}



###### stupid funny face
function funny_face() {
  _ret=$?; if test $_ret -ne 0; then echo "0_0->ret=$_ret"; set ?=$_ret; unset _ret; else echo "^_^"; fi
}



###### pretend to be busy in office to enjoy a cup of coffee
function grepcolor()
{
cat /dev/urandom | hexdump -C | grep --color=auto "ca fe"
}



###### a simple number guessing game
function hilow()
{
biggest=1000                            # maximum number possible
guess=0                                 # guessed by player
guesses=0                               # number of guesses made
number=$(( $$ % $biggest ))             # random number, 1 .. $biggest
while [ $guess -ne $number ] ; do
  echo -n "Guess? " ; read guess
  if [ "$guess" -lt $number ] ; then
    echo "... bigger!"
  elif [ "$guess" -gt $number ] ; then
    echo "... smaller!"
  fi
  guesses=$(( $guesses + 1 ))
done
echo "Right!! Guessed $number in $guesses guesses."
}


function oneliners()
{
w3m -dump_source http://www.onelinerz.net/random-one-liners/1/ | awk ' /.*<div id=\"oneliner_[0-9].*/ {while (! /\/div/ ) { gsub("\n", ""); getline; }; gsub (/<[^>][^>]*>/, "", $0); print $0}'
}



###### random cowsay stuff
function random_cow()
{
  files=(/usr/share/cowsay/cows/*)
  cat "${files[RANDOM % ${#files}]}"
}

##################################################
# Sudo stuff					 #
##################################################

###### Apt-get via sudo
# An apt-get wrapper function which will run the command via sudo, but will run it normally if you're only downloading source files.
# function apt-get() { [ "$1" = source ] && (command apt-get "$@";true) || sudo apt-get "$@" }



# function sudo()
# {
#   command="$@"
#   if [ -z "$command" ]; then
#     command sudo -s
#   else
#      command sudo "$@"
#   fi
# }



###### Wrap sudo to handle aliases and functions
# (enabled means all 'sudo' in this file need
# to be removed) (disabled for now by adding
# a single '#')
# function sudo()
# {
# local c o t parse
## Parse sudo args
# OPTIND=1
# while getopts xVhlLvkKsHPSb:p:c:a:u: t; do
# if [ "$t" = x ]; then
# parse=true
# else
# o="$o -$t"
# [ "$OPTARG" ] && o="$o $OPTARG"
# fi
# done
# shift $(( $OPTIND - 1 ))
## If no arguments are left, it's a simple call to sudo
# if [ $#  -ge 1 ]; then
# c="$1";
# shift;
# case $(type -t "$c") in
# "")
# echo No such command "$c"
# return 127
# ;;
# alias)
# c="$(type "$c"|sed "s/^.* to \`//;s/.$//")"
# ;;
# function)
# c=$(type "$c"|sed 1d)";\"$c\""
# ;;
# *)
# c="\"$c\""
# ;;
# esac
# if [ -n "$parse" ]; then
## Quote the rest once, so it gets processed by bash.
## Done this way so variables can get expanded.
# while [ -n "$1" ]; do
# c="$c \"$1\""
# shift
# done
# else
## Otherwise, quote the arguments. The echo gets an extra
## space to prevent echo from parsing arguments like -n
## Note the lovely interactions between " and ' ;-)
# while [ -n "$1" ]; do
# c="$c '$(echo " $1"|sed -e "s/^ //" -e "s/'/'\"'\"'/")'"
# shift
# done
# fi
## Run the command with verbose options
## echo Executing sudo $o -- bash -x -v -c "$c" >&2
# command sudo $o bash -xvc "$c"
# else
## echo sudo $o >&2
# command sudo $o
# fi
# }



###### Sudo for entire line (including pipes and redirects)
# USAGE: $ sudor your command
# This command uses a dirty hack with history, so be sure you not turned it off.
# WARNING!: This command behavior differ from other commands. It more like text macro, so you shouldn't use it in subshells, non-interactive sessions, other # functions/aliases and so on. You shouldn't pipe into sudor (any string that prefixes sudor will be removed), but if you really want, use this commands:
function proceed_sudo() { sudor_command="`HISTTIMEFORMAT=\"\" history 1 | sed -r -e 's/^.*?sudor//' -e 's/\"/\\\"/g'`" ; sudo sh -c "$sudor_command"; }; alias sudor="proceed_sudo # "



##################################################
# To show Apt Log History			 #
##################################################

function apt-history() {
      case "$1" in
        install)
              cat /var/log/dpkg.log | grep 'install '
              ;;
        upgrade|remove)
              cat /var/log/dpkg.log | grep $1
              ;;
        rollback)
              cat /var/log/dpkg.log | grep upgrade | \
                  grep "$2" -A10000000 | \
                  grep "$3" -B10000000 | \
                  awk '{print $4"="$5}'
              ;;
        *)
              cat /var/log/dpkg.log
              ;;
      esac
}



##################################################
# Undo apt-get build-dep (remove build		 #
# dependencies)					 #
##################################################

function aptitude-remove-dep() { sudo aptitude markauto $(apt-cache showsrc "$1" | grep Build-Depends | perl -p -e 's/(?:[\[(].+?[\])]|Build-Depends:|,|\|)//g'); }


###### convert phone numbers to letters/potentially english words
# Creator:	asmoore82
function phone2text()
{
echo -n "Enter number: "
read num
# Create a list of possibilites for expansion by the shell
# the "\}" is an ugly hack to get "}" into the replacment string -
# this is not a clean escape sequence - the litteral "\" is left behind!
num="${num//2/{a,b,c\}}"
num="${num//3/{d,e,f\}}"
num="${num//4/{g,h,i\}}"
num="${num//5/{j,k,l\}}"
num="${num//6/{m,n,o\}}"
num="${num//7/{p,q,r,s\}}"
num="${num//8/{t,u,v\}}"
num="${num//9/{w,x,y,z\}}"
# cleaup from the hack - remove all litteral \'s
num="${num//\\/}"
echo ""
echo "Possible words are:"
for word in $( eval echo "$num" )
do
    echo '>' "$word"
done
# End of File
}

##################################################
# Clock - A bash clock that can run in your	 #
# terminal window.				 #
##################################################

###### binary clock
function bclock()
{
watch -n 1 'echo "obase=2;`date +%s`" | bc'
}



###### binary clock
function bclock2()
{
perl -e 'for(;;){@d=split("",`date +%H%M%S`);print"\r";for(0..5){printf"%.4b ",$d[$_]}sleep 1}'
}



function clock()
{
while true;do clear;echo "===========";date +"%r";echo "===========";sleep 1;done
}

##################################################
# Bookmarking 					 #
##################################################

###### bookmarking the current directory in 'alias' form
function bookmark() {
	# copyright 2007 - 2010 Christopher Bratusek
	if [[ $1 != "" && $(alias | grep -w go-$1) == "" ]]; then
		echo "alias go-$1='cd $PWD'" >> $HOME/.bookmarks
		. $HOME/.bookmarks
	elif [[ $1 == "" ]]; then
		echo "need name for the bookmark."
	else	echo "bookmark go-$1 already exists."
	fi
}



function unmark() {
	# copyright 2007 - 2010 Christopher Bratusek
	if [[ $(alias | grep -w go-$1= ) != "" ]]; then
		sed -e "/go-$1/d" -i $HOME/.bookmarks
		xunalias go-$1
	fi
}


##################################################
# Create box of '#' characters around given 	 #
# string					 #
##################################################

function box() { t="$1xxxx";c=${2:-#}; echo ${t//?/$c}; echo "$c $1 $c"; echo ${t//?/$c}; }


##################################################
# Compress stuff				 #
##################################################

function compress_() {
   # Credit goes to: Daenyth
   FILE=$1
   shift
   case $FILE in
      *.tar.bz2) tar cjf $FILE $*  ;;
      *.tar.gz)  tar czf $FILE $*  ;;
      *.tgz)     tar czf $FILE $*  ;;
      *.zip)     zip $FILE $*      ;;
      *.rar)     rar $FILE $*      ;;
      *)         echo "Filetype not recognized" ;;
   esac
}

##################################################
# Cp with progress bar (using pv)		 #
##################################################

function cp_p() {
	if [ `echo "$2" | grep ".*\/$"` ]
	then
		pv "$1" > "$2""$1"
	else
		pv "$1" > "$2"/"$1"
	fi
}


##################################################
# Super stealth background launch		 #
##################################################

function daemon()
{
    (exec "$@" >&/dev/null &)
}

##################################################
# Site down for everyone or just me?		 #
##################################################

function downforme() {
	RED='\e[1;31m'
	GREEN='\e[1;32m'
	YELLOW='\e[1;33m'
	NC='\e[0m'
	if [ $# = 0 ]
	then
		echo -e "${YELLOW}usage:${NC} downforme website_url"
	else
		JUSTYOUARRAY=(`lynx -dump http://downforeveryoneorjustme.com/$1 | grep -o "It's just you"`)
		if [ ${#JUSTYOUARRAY} != 0 ]
		then
			echo -e "${RED}It's just you. \n${NC}$1 is up."
		else
			echo -e "${GREEN}It's not just you! \n${NC}$1 looks down from here."
		fi
	fi
}

##################################################
# Surround lines with quotes (useful in pipes)	 #
# - from mervTormel				 #
##################################################

function enquote() { /bin/sed 's/^/"/;s/$/"/' ; }

##################################################
# Extract - extract most common compression	 #
# types						 #
##################################################

function extract() {
  local e=0 i c
  for i; do
    if [[ -f $i && -r $i ]]; then
        c=''
        case $i in
          *.t@(gz|lz|xz|b@(2|z?(2))|a@(z|r?(.@(Z|bz?(2)|gz|lzma|xz)))))
                 c='bsdtar xvf' ;;
          *.7z)  c='7z x'       ;;
          *.Z)   c='uncompress' ;;
          *.bz2) c='bunzip2'    ;;
          *.exe) c='cabextract' ;;
          *.gz)  c='gunzip'     ;;
          *.rar) c='unrar x'    ;;
          *.xz)  c='unxz'       ;;
          *.zip) c='unzip'      ;;
          *)     echo "$0: cannot extract \`$i': Unrecognized file extension" >&2; e=1 ;;
        esac
        [[ $c ]] && command $c "$i"
    else
        echo "$0: cannot extract \`$i': File is unreadable" >&2; e=2
    fi
  done
  return $e
}

##################################################
# Progress visuals				 #
##################################################

###### display animated hourglass in the shell to indicate ongoing processing
function hourglass() { s=$(($SECONDS +${1:-10}));(tput civis;while [[ $SECONDS -lt $s ]];do for f in '|' ' ' '\-' /;do echo -n $f&&sleep .2s&&tput cub1;done;done);tput cnorm; }



###### pretty progressbar
function progressbar()
# copyright 2007 - 2010 Christopher Bratusek
{
	SP_COLOUR="\e[37;44m"
	SP_WIDTH=5.5
	SP_DELAY=0.2
	SP_STRING=${2:-"'|/=\'"}
	while [ -d /proc/$1 ]
	do
		printf "$SP_COLOUR\e7  %${SP_WIDTH}s  \e8\e[01;37m" "$SP_STRING"
		sleep ${SP_DELAY:-.2}
		SP_STRING=${SP_STRING#"${SP_STRING%?}"}${SP_STRING%?}
	done
	tput sgr0
}



###### please wait...
# copyright 2007 - 2010 Christopher Bratusek
function spanner() {
	PROC=$1;COUNT=0
	echo -n "Please wait "
	while [ -d /proc/$PROC ];do
		while [ "$COUNT" -lt 10 ];do
			echo -ne '\x08  ' ; sleep 0.1
			((COUNT++))
		done
		until [ "$COUNT" -eq 0 ];do
			echo -ne '\x08\x08 ' ; sleep 0.1
			((COUNT -= 1))
		done
	done
}



function spin() {
	# copyright 2007 - 2010 Christopher Bratusek
        echo -n "|/     |"
        while [ -d /proc/$1 ]
        do
        # moving right
        echo -ne "\b\b\b\b\b\b\b-     |"
        sleep .05
        echo -ne "\b\b\b\b\b\b\b\\     |"
        sleep .05
        echo -ne "\b\b\b\b\b\b\b|     |"
        sleep .05
        echo -ne "\b\b\b\b\b\b\b /    |"
        sleep .05
        echo -ne "\b\b\b\b\b\b-    |"
        sleep .05
        echo -ne "\b\b\b\b\b\b\\    |"
        sleep .05
        echo -ne "\b\b\b\b\b\b|    |"
        sleep .05
        echo -ne "\b\b\b\b\b\b /   |"
        sleep .05
        echo -ne "\b\b\b\b\b-   |"
        sleep .05
        echo -ne "\b\b\b\b\b\\   |"
        sleep .05
        echo -ne "\b\b\b\b\b|   |"
        sleep .05
        echo -ne "\b\b\b\b\b /  |"
        sleep .05
        echo -ne "\b\b\b\b-  |"
        sleep .05
        echo -ne "\b\b\b\b\\  |"
        sleep .05
        echo -ne "\b\b\b\b|  |"
        sleep .05
        echo -ne "\b\b\b\b / |"
        sleep .05
        echo -ne "\b\b\b- |"
        sleep .05
        echo -ne "\b\b\b\\ |"
        sleep .05
        echo -ne "\b\b\b| |"
        sleep .05
        echo -ne "\b\b\b /|"
        sleep .05
        echo -ne "\b\b-|"
        sleep .05
        echo -ne "\b\b\\|"
        sleep .05
        echo -ne "\b\b||"
        sleep .05
        echo -ne "\b\b/|"
        sleep .05
        # moving left
        echo -ne "\b\b||"
        sleep .05
        echo -ne "\b\b\\|"
        sleep .05
        echo -ne "\b\b-|"
        sleep .05
        echo -ne "\b\b\b/ |"
        sleep .05
        echo -ne "\b\b\b| |"
        sleep .05
        echo -ne "\b\b\b\\ |"
        sleep .05
        echo -ne "\b\b\b- |"
        sleep .05
        echo -ne "\b\b\b\b/  |"
        sleep .05
        echo -ne "\b\b\b\b|  |"
        sleep .05
        echo -ne "\b\b\b\b\\  |"
        sleep .05
        echo -ne "\b\b\b\b-  |"
        sleep .05
        echo -ne "\b\b\b\b\b/   |"
        sleep .05
        echo -ne "\b\b\b\b\b|   |"
        sleep .05
        echo -ne "\b\b\b\b\b\\   |"
        sleep .05
        echo -ne "\b\b\b\b\b-   |"
        sleep .05
        echo -ne "\b\b\b\b\b\b/    |"
        sleep .05
        echo -ne "\b\b\b\b\b\b|    |"
        sleep .05
        echo -ne "\b\b\b\b\b\b\\    |"
        sleep .05
        echo -ne "\b\b\b\b\b\b-    |"
        sleep .05
        echo -ne "\b\b\b\b\b\b\b/     |"
        sleep .05
        done
	echo -e "\b\b\b\b\b\b\b\b\b|=======| done!"
}



function spinner()
# copyright 2007 - 2010 Christopher Bratusek
{
	PROC=$1
	while [ -d /proc/$PROC ];do
		echo -ne '\e[01;32m/\x08' ; sleep 0.05
		echo -ne '\e[01;32m-\x08' ; sleep 0.05
		echo -ne '\e[01;32m\\\x08' ; sleep 0.05
		echo -ne '\e[01;32m|\x08' ; sleep 0.05
	done
}



###### Display a progress process
# To start the spinner2 function, you have to send the function
# into the background. To stop the spinner2 function, you have
# to define the argument "stop".
# EXAMPLE:
#    echo -n "Starting some daemon "; spinner2 &
#    if sleep 10; then
#       spinner2 "stop"; echo -e "\t[ OK ]"
#    else
#       spinner2 "stop"; echo -e "\t[ FAILED ]"
#    fi
function spinner2() {
      local action=${1:-"start"}
      declare -a sign=( "-" "/" "|" "\\\\" )
      # define singnal file...
      [ "$action" = "start" ] && echo 1 > /tmp/signal
      [ "$action" = "stop" ] && echo 0 > /tmp/signal
      while [ "$( cat /tmp/signal 2>/dev/null )" == "1" ] ; do
          for (( i=0; i<${#sign[@]}; i++ )); do
              echo -en "${sign[$i]}\b"
              # with this command you can use millisecond as sleep time - perl rules ;-)
              perl -e 'select( undef, undef, undef, 0.1 );'
          done
      done
      # clear the last ${sign[$i]} sign at finish...
      [ "$action" = "stop" ] && echo -ne " \b"
}



function working()
# copyright 2007 - 2010 Christopher Bratusek
{
   while [ -d /proc/$1 ]
   do
	echo -ne "w      \b\b\b\b\b\b\b";sleep .08;
	echo -ne "wo     \b\b\b\b\b\b\b";sleep .08;
	echo -ne "wor    \b\b\b\b\b\b\b";sleep .08;
	echo -ne "work   \b\b\b\b\b\b\b";sleep .08;
	echo -ne "worki  \b\b\b\b\b\b\b";sleep .08;
	echo -ne "workin \b\b\b\b\b\b\b";sleep .08;
	echo -ne "working\b\b\b\b\b\b\b";sleep .08;
	echo -ne " orking\b\b\b\b\b\b\b";sleep .08;
	echo -ne "  rking\b\b\b\b\b\b\b";sleep .08;
	echo -ne "   king\b\b\b\b\b\b\b";sleep .08;
	echo -ne "    ing\b\b\b\b\b\b\b";sleep .08;
	echo -ne "     ng\b\b\b\b\b\b\b";sleep .08;
	echo -ne "      g\b\b\b\b\b\b\b";sleep .08;
   done
}


##################################################
# List your MACs address			 #
##################################################

function lsmac() { ifconfig -a | awk '/HWaddr/ {print $5}' ; }

##################################################
# Morse code encoding and decoding		 #
##################################################

###### this is a short Morse code decoder written as a shellscript using sed
# the Morse coded text should be written with spaces between the letters
# only good to convert from Morse code to text
# by scvalex
function morse2text()
{
echo $1\  | tr . 0 | sed -e {s/0----\ /1/g} -e {s/00---\ /2/g} -e {s/000--\ /3/g} -e {s/000-\ /4/g} -e {s/00000\ /5/g} -e {s/-0000\ /6/g} -e {s/--000\ /7/g} -e {s/---00\ /8/g} -e {s/----0\ /9/g} -e {s/-----\ /0/g} \
	| sed -e {s/-0-0\ /c/g} -e {s/-000\ /b/g} -e {s/00-0\ /f/g} -e {s/0000\ /h/g} -e {s/0---\ /j/g} -e {s/0-00\ /l/g} -e {s/0--0\ /p/g} -e {s/--0-\ /q/g} -e {s/000-\ /v/g} -e {s/-00-\ /x/g} -e {s/-0--\ /y/g} -e {s/--00\ /z/g} \
	| sed -e {s/0--\ /w/g} -e {s/-00\ /d/g} -e {s/--0\ /g/g} -e {s/-0-\ /k/g} -e {s/---\ /o/g} -e {s/0-0\ /r/g} -e {s/000\ /s/g} -e {s/00-\ /u/g} \
	| sed -e {s/0-\ /a/g} -e {s/00\ /i/g} -e {s/--\ /m/g} -e {s/-0\ /n/g} \
	| sed -e {s/0\ /e/g} -e {s/-\ /t/g}
}



function text2morse()
{
cat > "/tmp/text2morse.py" <<"End-of-message"
#!/usr/bin/python
# short mark, dot or 'dit' (.) = .
# longer mark, dash or 'dah' (-) = -
# intra-character gap (between the dots and dashes within a character) = no space
# short gap (between letters) = single space
# medium gap (between words) = double space
import sys
__author__="Aanand Natarajan"
# morse code dictionary
codes = {'1':".----",'2':"..---",'3':"...--",'4':"....-",'5':".....",'6':"-....",'7':"--...",'8':"---..",
'9':"----.",'0':"-----",'A':".-",'B':"-...",'C':"-.-.",'D':"-..",'E':".",'F':"..-.",'G':"--.",
'H':"....",'I':"..",'J':".---",'K':"-.-",'L':".-..",'M':"--",'N':"-.",'O':"---",'P':".--.",
'Q':"--.-",'R':".-.",'S':"...",'T':"-",'U':"..-",'V':"...-",'W':".--",'X':"-..-",'Y':"-.--",
'Z':"--..",
# punctuations
',':"--..--",'.':".-.-.-",'?':"..--..",';':"-.-.-",':':"---...",'/':"-..-.",
'-':"-....-","'":".----.",'(':"-.--.",')':"-.--.-",'!':"-.-.--",'&':".-...",
'=':"-...-",'+':".-.-.",'_':"..--.-",'"':".-..-.",'$':"...-..-",'@':".--.-.",
# space
' ':"|"}
binary = {'.':'.','-':'-',',':' ','|':'  '}
def encode(value):
    """ encodes the value into morse code """
    morse_value=""
    value.replace('*', 'X')
    value.replace('^', 'XX')
    for c in value:
       try :
               morse_value += codes[c.upper()]+','
       except :
         print ("Unintended character " + c + " omitted")
    return _get_binary(morse_value)
def decode(morse_code_value):
    """ decodes the morse bytes """
    decoded_value = _decode_binary(morse_code_value)
    ascii_value=""
    for v in decoded_value.split(","):
        ascii_value += _get_key(v)
    return ascii_value
def _get_binary(value):
     binary_value = ""
     for c in value:
         binary_value += binary[c]
     return binary_value
def _get_key(value):
     """ returns the key for the given value """
     for k,v in codes.items():
         if v == value:
            return k
     return ''
def _decode_binary(binary):
    dah_replaced = binary.replace('-', '-')
    dit_replaced = dah_replaced.replace('.', '.')
    comma_replaced = dit_replaced.replace(' ', ',')
    zero_replaced = comma_replaced.replace('', '|,')
    return zero_replaced
def _do_decode(value):
    print (	"Decoded : "+decode(value))
def _do_encode(value):
    print ("Encoded : "+encode(value))
if __name__ == "__main__":
   if len(sys.argv) > 2:
      if sys.argv[1] == 'd' :
         print ("decoding")
         _do_decode(sys.argv[2])
      else:
         print ("encoding")
         _do_encode(sys.argv[2])
   elif len(sys.argv) > 1:
        print ("encoding")
        _do_encode(sys.argv[1])
   else:
        print ("Usage : "+sys.argv[0]+" [d (decode) |e (encode)] [input string]")
End-of-message
chmod +x "/tmp/text2morse.py"
"/tmp/text2morse.py" "$1"
rm "/tmp/text2morse.py"
}


##################################################
# Scans a port, returns what's on it.		 #
##################################################

function port() {
lsof -i :"$1"
}


##################################################
# X DISPLAY functions				 #
##################################################

function reset_display()
{
    if [ "$SHLVL" -eq 1 ]; then
        echo $DISPLAY > $HOME/.display
    else
        if [ -e $HOME/.display ]; then
            export DISPLAY=$(cat $HOME/.display)
        fi
    fi
}



function set_xtitle()
{
    if [ $TERM == "xterm" ]; then
        echo -ne "\033]0;${USER}@${HOSTNAME}: ${PWD}\007"
    fi
}
# if [ "$UID" -ne 0 ]; then
#     reset_display
# fi

##################################################
# Ssh functions					 #
##################################################

function slak()
{
    if [ $# -lt 2 ]; then
        echo "add public key to securelink server"
        echo "usage: skak [accountname] [sl port]"
    else
        cat /Volumes/Library/ssh/id_rsa-$1.pub | ssh -q lila@localhost -p $2 "if [ ! -d ~/.ssh/ ] ; then mkdir ~/.ssh ; fi ; chmod 700 ~/.ssh/ ; cat - >> ~/.ssh/authorized_keys ; chmod 600 ~/.ssh/authorized_keys"
    fi
}



function slssh()
{
    if [ $# -lt 1 ]; then
        echo "connect to securelink ssh session"
        echo "usage slssh [port#]"
        echo "ssh -p \$1 localhost"
    else
        ssh -p $1 localhost
    fi
}



function slpg()
{
    if [ $# -lt 1 ]; then
        echo "create securelink ssh tunnel for postgres"
        echo "usage: slpg [port#]"
        echo "ssh -N localhost -L 2345/localhost/5432 -p \$1"
    else
        ssh -N localhost -L 2345/localhost/5432 -p $1
    fi
}



function sshmysql()
{
# bind MySQL hostport to forward remote MySQL connection to localhost
ssh -L 13306:127.0.0.1:3306 -N $* &
}



function sshpg()
{
    if [ $# -lt 1 ]; then
        echo "create ssh tunnel for postgres"
        echo "usage: sshpg username@server"
        echo "ssh -N \$1 -L 2345/localhost/5432"
    else
        ssh -N $1 -L 2345/localhost/5432
    fi
}



function sshpg2()
{
    if [ $# -lt 1 ]; then
        echo "create ssh tunnel for postgres"
        echo "usage: sshpg username@server"
        echo "ssh -N \$1 -L \$2/localhost/5432"
    else
        ssh -N $1 -L $2/localhost/5432
    fi
}



##################################################
# Stopwatch and Countdown Timer			 #
##################################################

function stopwatch() {
# copyright 2007 - 2010 Christopher Bratusek
BEGIN=$(date +%s)
while true; do
    NOW=$(date +%s)
    DIFF=$(($NOW - $BEGIN))
    MINS=$(($DIFF / 60))
    SECS=$(($DIFF % 60))
    echo -ne "Time elapsed: $MINS:`printf %02d $SECS`\r"
    sleep .1
done
}



###### stopwatch with log
function stop_watch()
{
START=$( date +%s ); while true; do CURRENT=$( date +%s ) ; echo $(( CURRENT-START )) ; sleep 1 ; echo -n; done
}



###### countdown clock
function countdown() { case "$1" in -s) shift;; *) set $(($1 * 60));; esac; local S=" "; for i in $(seq "$1" -1 1); do echo -ne "$S\r $i\r"; sleep 1; done; echo -e "$S\rBOOM!"; }



###### countdown clock
alias countdown2='MIN=1 && for i in $(seq $(($MIN*60)) -1 1); do echo -n "$i, "; sleep 1; done; echo -e "\n\nBOOOM! Time to start."'


##################################################
# Transcodes and streams a video over http on	 #
# port 6789 (vlc required)			 #
##################################################

function stream() { 
	cvlc $1 --extraintf rc --sout 'transcode{vcodec=h264,vb=256,fps=12,scale=1,deinterlace,acodec=mp3,threads=3,ab=64,channels=2}:duplicate{dst=std{access=http,mux=ts,dst=0.0.0.0:6789}}';
}

##################################################
# Touchpad stuff				 #
##################################################

###### to get information on touchpad
alias touchpad_id='xinput list | grep -i touchpad'



###### to disable touchpad
# using 'touchpad_id', set the number for your touchpad (default is 12)
function touchpad_off()
{
touchpad=11
xinput set-prop $touchpad "Device Enabled" 0
}



###### to enable touchpad
# using 'touchpad_id', set the number for your touchpad (default is 12)
function touchpad_on()
{
touchpad=11
xinput set-prop $touchpad "Device Enabled" 1
}

##################################################
# Timer function				 #
##################################################

###### Elapsed time.  Usage:
#   t=$(timer)
#   ... # do something
#   printf 'Elapsed time: %s\n' $(timer $t)
#      ===> Elapsed time: 0:01:12
# If called with no arguments a new timer is returned.
# If called with arguments the first is used as a timer
# value and the elapsed time is returned in the form HH:MM:SS.
function timer()
{
    if [[ $# -eq 0 ]]; then
        echo $(date '+%s')
    else
        local  stime=$1
        etime=$(date '+%s')
        if [[ -z "$stime" ]]; then stime=$etime; fi
        dt=$((etime - stime))
        ds=$((dt % 60))
        dm=$(((dt / 60) % 60))
        dh=$((dt / 3600))
        printf '%d:%02d:%02d' $dh $dm $ds
    fi
}

##################################################
# Checks to ensure that all 			 #
# environment variables are valid		 #
##################################################

###### looks at SHELL, HOME, PATH, EDITOR, MAIL, and PAGER
function validator()
{
errors=0
function in_path()
{
  # given a command and the PATH, try to find the command. Returns
  # 1 if found, 0 if not.  Note that this temporarily modifies the
  # the IFS input field seperator, but restores it upon completion.
  cmd=$1    path=$2    retval=0
  oldIFS=$IFS; IFS=":"
  for directory in $path
  do
    if [ -x $directory/$cmd ] ; then
      retval=1      # if we're here, we found $cmd in $directory
    fi
  done
  IFS=$oldIFS
  return $retval
}
function validate()
{
  varname=$1    varvalue=$2
  if [ ! -z $varvalue ] ; then
    if [ "${varvalue%${varvalue#?}}" = "/" ] ; then
      if [ ! -x $varvalue ] ; then
        echo "** $varname set to $varvalue, but I cannot find executable."
        errors=$(( $errors + 1 ))
      fi
    else
      if in_path $varvalue $PATH ; then
        echo "** $varname set to $varvalue, but I cannot find it in PATH."
        errors=$(( $errors + 1 ))
      fi
    fi
  fi
}
####### Beginning of actual shell script #######
if [ ! -x ${SHELL:?"Cannot proceed without SHELL being defined."} ] ; then
  echo "** SHELL set to $SHELL, but I cannot find that executable."
  errors=$(( $errors + 1 ))
fi
if [ ! -d ${HOME:?"You need to have your HOME set to your home directory"} ]
then
  echo "** HOME set to $HOME, but it's not a directory."
  errors=$(( $errors + 1 ))
fi
# Our first interesting test: are all the paths in PATH valid?
oldIFS=$IFS; IFS=":"     # IFS is the field separator. We'll change to ':'
for directory in $PATH
do
  if [ ! -d $directory ] ; then
      echo "** PATH contains invalid directory $directory"
      errors=$(( $errors + 1 ))
  fi
done
IFS=$oldIFS             # restore value for rest of script
# Following can be undefined, & also be a progname, rather than fully qualified path.
# Add additional variables as necessary for your site and user community.
validate "EDITOR" $EDITOR
validate "MAILER" $MAILER
validate "PAGER"  $PAGER
# and, finally, a different ending depending on whether errors > 0
if [ $errors -gt 0 ] ; then
  echo "Errors encountered. Please notify sysadmin for help."
else
  echo "Your environment checks out fine."
fi
}

##################################################
# Text message on wallpaper			 #
##################################################

function wallpaperWarn() { BG="/desktop/gnome/background/picture_filename"; convert "`gconftool-2 -g $BG`" -pointsize 70 -draw "gravity center fill red  text 0,-360 'Warn' fill white  text 0,360 'Warn'" /tmp/w.jpg; gconftool-2 --set $BG -t string "/tmp/w.jpg" ; }

##################################################
# Check hosts that are online			 #
##################################################

###### for those who DO NOT USE their /etc/hosts file for name resolution
# Function whoisonline adapted by:	dewar1
# This can look through resolv.conf file for address of nameservers
# (note: THIS WILL ONLY WORK IF YOU USE LOCAL NAMESERVERS! Nameservers
# from your ISP will render this function useless). It then cuts result to
# show just first 3 octets of IP address and runs nmap just as original function.
if which nmap 2>&1 > /dev/null; then
  function whodat()
  {
    if [ -n "$1" ]; then
      net="$1"
    else
      net=$(cat /etc/resolv.conf | grep 'nameserver' | cut -c12-26 | awk -F '.' '{print $1"."$2"."$3".0/24"}')
    fi
    echo "testing $net for online hosts"
    nmap -sP $net | awk '/Host/ && /up/ { print $0; }'
    echo "done"
  }
fi



###### for those who USE their /etc/hosts file for name resolution
#if which nmap 2>&1 > /dev/null; then
#  function whoisonline()
#  {
#    if [ -n "$1" ]; then
#      net="$1"
#    else
#      net=$(grep `hostname` /etc/hosts | awk -F '.' '{ print $1"."$2"."$3".0/24"}')
#    fi
#    sh_info "testing $net for online boxes"
#    sudo nmap -sP $net | awk '/Host/ && /up/ { print $0; }'
#    sh_success "done"
#  }
#fi

######################################################################################################################################################
###### ALIASES ###### ALIASES ###### ALIASES ###### ALIASES ###### ALIASES ###### ALIASES ###### ALIASES ###### ALIASES ###### ALIASES ###### ALIASES ######
######################################################################################################################################################








##################################################
# App-specific					 #
##################################################

alias audio='ncmpcpp'									# music player
alias compiz-reset='gconftool-2 --recursive-unset /apps/compiz-1 && unity --reset'	# to reset Compiz
alias daemon-status='for a in deluged deluge rtorrent; do  (ps -u $USER|grep $a$ > /dev/null && echo $a running.) || echo $a not running.; done'											# list the status of the daemons :p
alias daggerfall='dosbox -conf ~/.dosbox.conf.daggerfall'				# launch dosbox with preset config for Daggerfall
# alias deluge-link='echo http://'`hostname`':'$USER_WPRT'/'
alias ftp='ncftp Personal'
alias gnome-fallback-session='gsettings set org.gnome.desktop.session session-name "gnome-fallback"'	# GNOME3 desktop session
alias gnome-fallback-set='sudo /usr/lib/lightdm/lightdm-set-defaults -s gnome-fallback'			# auto login under set GNOME3 desktop
alias gnome-shell-reset='gnome-shell --replace'						# to reset Gnome Shell
alias gnome-shell-session='gsettings set org.gnome.desktop.session session-name "gnome-shell"'		# GNOME3 desktop session
alias gnome-shell-set='sudo /usr/lib/lightdm/lightdm-set-defaults -s gnome-shell'			# auto login under set GNOME3 desktop
alias instaluj='sudo pacman-color -S'
alias links2g='links2 -g'
alias nano='nano -W -m'									# disable annoying line wrapping
alias notify-osd-reset='pkill notify-osd'						# to reset notify-osd (handy for Leolik's customized notify-osd)
alias pacclean='sudo yaourt -Scc' 							# clean package cache
alias pacin='sudo yaourt -S'  								# install a specific package
alias pacman='yaourt' 									# switches from Pacman to Yaourt so can troll AUR
alias pacout='sudo yaourt -Rs'								# Remove a specific package
alias pacsync='sudo yaourt -Sy'   							# Sync
alias pacup='sudo yaourt -Syu'								# Sync & Update
alias rc='ssh ${MEDIAPCHOSTNAME} env DISPLAY=:0.0 rhythmbox-client --no-start'		# remote control for Rhythmbox on an Ubuntu Media PC
alias refresh='nautilus -q && gconftool-2 --shutdown && pkill gnome-panel'		# safely close/refresh nautilus and gnome-panel
alias scrot='scrot -c -d 7'
alias skypefix='mv ~/.Skype/shared.xml ~/.Skype/shared~.xml'				# Skype fix for inability to log back in crash
alias spotify_next='$HOME/spotifycmd/spotify_cmd.exe next; $HOME/spotifycmd/spotify_cmd.exe status'
alias spotify_playpause='$HOME/spotifycmd/spotify_cmd.exe playpause'
alias spotify_prev='$HOME/spotifycmd/spotify_cmd.exe prev; $HOME/spotifycmd/spotify_cmd.exe status'
alias spotify_status='$HOME/spotifycmd/spotify_cmd.exe status'
alias spotify_stop='$HOME/spotifycmd/spotify_cmd.exe stop'
alias ss='gnome-screensaver-command -a'
alias start-deluged='start-stop-daemon -S --pidfile $HOME/.deluged.pid -u $USER -d $HOME -a /usr/bin/deluged -- --pidfile $HOME/.deluged.pid'
alias start-deluge-webui='start-stop-daemon -S --pidfile $HOME/.deluge-web.pid --background --make-pidfile -u $USER -d $HOME -a /usr/bin/deluge --  -u web'
alias start-rtorrent='(screen -ls|grep rtorrent > /dev/null || (screen -dmS rtorrent rtorrent && false)) && echo rtorrent is already running.'
alias start-vnc='vncserver :$USER_VPRT'
alias stop-deluged='start-stop-daemon -K --pidfile $HOME/.deluged.pid -u $USER -d $HOME -a /usr/bin/deluged -- --pidfile $HOME/.deluged.pid || killall -v -u $USER deluged'
alias stop-deluge-webui='start-stop-daemon -K --pidfile $HOME/.deluge-web.pid --make-pidfile -u $USER -d $HOME -a /usr/bin/deluge --  -u web;rm $HOME/.deluge-web.pid;'
alias stop-rtorrent='killall -u $USER rtorrent -q || echo rtorrent is not running'
alias stop-vnc='vncserver -kill :$USER_VPRT'
alias tetris='bastet' 									# bastardly tetris... awesome but deadly
alias tvtime-video0='tvtime-configure -d /dev/video0'
alias tvtime-video1='tvtime-configure -d /dev/video1'
alias tvtime-video2='tvtime-configure -d /dev/video2'
alias tvtime-video3='tvtime-configure -d /dev/video3'
alias tvtime-video4='tvtime-configure -d /dev/video4'
alias tvtime-video5='tvtime-configure -d /dev/video5'
alias unity-reset-icons='unity --reset-icons' 						# to reset Unity launcher icons
alias unity-reset='unity --reset'							# to reset Unity
alias unity-session='gsettings set org.gnome.desktop.session session-name "unity"'	# GNOME3 desktop session
alias unity-set='sudo /usr/lib/lightdm/lightdm-set-defaults -s unity'			# auto login under set GNOME3 desktop
alias wgeturlfromfile='wget -r -l1 -H -t1 -nd -N -np -A.jpg -erobots=off -i'		# -i file.txt
alias wget='wget -c'
alias yr='yaourt -Rs -C'
alias yss='yaourt -Ss -C'
alias ys='yaourt -S -C'
alias ysyu='yaourt -Syu -C'
alias ysy='yaourt -Sy -C'



##################################################
# Apt-cache stuff				 #
##################################################

alias aptadd='sudo apt-cache add'
alias aptdepends='apt-cache depends'
alias aptdotty='sudo apt-cache dotty'
alias aptdumpavail='sudo apt-cache dumpavail'
alias aptdump='apt-cache dump'
alias aptgencaches='sudo apt-cache gencaches'
alias aptpkgnames='apt-cache pkgnames'
alias aptpolicy='apt-cache policy'
alias aptrdepends='apt-cache rdepends'
alias aptsearch='apt-cache search'
alias aptshowpkg='apt-cache showpkg'
alias aptshowsrc='apt-cache showsrc'
alias aptshow='apt-cache show'
alias aptstats='apt-cache stats'
alias aptunmet='apt-cache unmet'
alias aptxvcg='sudo apt-cache xvcg'



##################################################
# Apt-get stuff					 #
##################################################

alias autoremove='sudo apt-get autoremove'
alias check='sudo apt-get check'
alias dist-upgrade='sudo apt-get dist-upgrade'
alias dselect-upgrade='sudo apt-get dselect-upgrade'
alias source='sudo apt-get source'



##################################################
# Apt-history Stuff				 #
##################################################

alias historya='apt-history'
alias historyi='apt-history install'
alias historyre='apt-history remove'
alias historyro='apt-history rollback'
alias historyu='apt-history upgrade'



##################################################
# Aptitude stuff				 #
##################################################

alias autoclean='sudo aptitude autoclean'
alias build-dep='sudo aptitude build-dep'
alias changelog='aptitude changelog'
alias clean='sudo aptitude clean'
alias download='aptitude download'
alias forbid-version='sudo aptitude forbid-version'
alias forget-new='sudo aptitude forget-new'
alias full-upgrade='sudo aptitude full-upgrade'
alias hold='sudo aptitude hold'
alias install='sudo aptitude install -y'
alias linux-image='aptitude search linux-image'			# linux-image kernel update check
alias markauto='sudo aptitude markauto'
alias purge='sudo aptitude purge'
alias reinstall='sudo aptitude reinstall'
alias remove='sudo aptitude remove'
alias search='aptitude search'
alias show='aptitude show'
alias unhold='sudo aptitude unhold'
alias unmarkauto='sudo aptitude unmarkauto'
alias update='sudo aptitude update'
alias upgrade='sudo aptitude safe-upgrade'
alias why-not='aptitude why-not'
alias why='aptitude why'



##################################################
# Chown substitution				 #
##################################################

alias chown-backgrounds='sudo chown -R $USER:$USER ~/Pictures/Backgrounds'
alias chown-backups='sudo chown -R $USER:$USER ~/Backups'
alias chown-books='sudo chown -R $USER:$USER ~/eBooks'
alias chown-desktop='sudo chown -R $USER:$USER ~/Desktop'
alias chown-documents='sudo chown -R $USER:$USER ~/Documents'
alias chown-downloads='sudo chown -R $USER:$USER ~/Downloads'
alias chown-drive-c='sudo chown -R $USER:$USER ~/.wine/drive_c'
alias chown-home='sudo chown -R $USER:$USER ~/'
alias chown-images='sudo chown -R $USER:$USER ~/Images'
alias chown-localhost='sudo chown -R $USER:$USER ~/var/www'
alias chown-music='sudo chown -R $USER:$USER ~/Music'
alias chown-nautilus-scripts='sudo chown -R $USER:$USER ~/.gnome2/nautilus-scripts'
alias chown-nemo-scripts='sudo chown -R $USER:$USER ~/.gnome2/nemo-scripts'
alias chown-packages='sudo chown -R $USER:$USER ~/Packages'
alias chown-pictures='sudo chown -R $USER:$USER ~/Pictures'
alias chown-ppc='sudo chown -R $USER:$USER ~/PPC'
alias chown-public='sudo chown -R $USER:$USER ~/Public'
alias chown='sudo chown -R $USER:$USER'
alias chown-temp='sudo chown -R $USER:$USER ~/Temp'
alias chown-torrents='sudo chown -R $USER:$USER ~/Torrents'
alias chown-ubuntu-texts='sudo chown -R $USER:$USER ~/Documents/"Ubuntu Texts"'
alias chown-videos='sudo chown -R $USER:$USER ~/Videos'



##################################################
# Command substitution				 #
##################################################

alias abs='sudo abs'
alias a='ssh-agent;ssh-add'
alias br='sudo service bluetooth restart'						# restart Bluetooth from terminal
alias bt='aria2c --max-upload-limit=10K --seed-time=60 --listen-port=8900-8909'		# shortcut for downloading a torrent file on the command line
alias c='clear'
alias ci='vim'
alias ck='killall conky && conky -d'
alias cls='clear'
alias cn_='cat > /dev/null'								# for pasting code/data into terminal without it doing anything
alias contents='/bin/tar -tzf'								# can View the contents of a Tar file
alias cp='cp -iv'
alias d_='ssh 192.168.1.4'
alias dr='dirs -v'
alias ds_='dig +noauthority +noadditional +noqr +nostats +noidentify +nocmd +noquestion +nocomments'		# short and sweet output from dig(1)
alias e='espeak'
alias egrep='egrep –color=auto'
alias enote='vi ~/todo;~/motd.pl'
alias fgrep='fgrep –color=auto'
alias ge='geany'
alias grep='grep --color=auto'								# highlight matched pattern
alias g_='mocp -G'
alias halt='sudo /sbin/halt'
alias h='history | grep $1'
alias hib='sudo pm-hibernate'
alias ie='wine iexplore.exe'								# browse the Internet using Internet Explorer
alias im='centerim'  									# terminal based instant messaging client
alias img='imgurbash' 									# uploads image to imgur
alias irc='irssi' 									# terminal based IRC
# alias irssi='screen -wipe; screen -A -U -x -R -S irssi irssi'				# for creating screen session containing IRSSI, named irssi, while checking if existing session is created
alias j='jobs -l'
alias kfx='killall firefox-bin'
alias kgp='killall gnome-panel'
alias k='kill'
alias kk='sendmail -d0.4 -bv root |less'
alias kn='killall nautilus'
alias last='last -a'
alias lock='clear && vlock -c'								# clear and lock console (non-X) terminal
alias logs='tail -f /var/log/messages /var/log/*log'
alias m='~/bin/motd.pl'
alias mc='metacafe-dl -t'
alias me_='vi ~/.muttrc'
alias mkdir='mkdir -p -v'
alias mktd='tdir=`mktemp -d` && cd $tdir'						# make a temp dir, then immediately cd into it
alias m=mutt
alias more='less'
alias mp='screen -d -m mousepad'
alias mv='mv -iv'
alias na='nano'
alias n='nautilus & exit'
alias np='mpc --format "np: [[%artist%] - [%title%] - 					#[[%album%] ##[%track%]#]]|[%file%]" | head -n 1'
alias nq='nautilus -q'
alias oe='wine msimn.exe'								# read email with Outlook Express
alias packup='/bin/tar -czvf'								# compress a file in tar format
alias parts='cat /proc/partitions'
# alias paste='ix'  									# pastes to ix.ox pastebin service
alias paste_='pastebinit'
alias path='echo -e ${PATH//:/\\n}'
alias pe='vi ~/.procmailrc'
alias pg='ps aux | grep'*								# requires an argument
alias pi='`cat ~/.pi | grep ' ; alias addpi='echo "cd `pwd`" >> ~/.pi'			# fast access to any of your favorite directory.
alias ping='ping -c 10'
alias pjet='enscript -h -G -fCourier9 -d $LPDEST'           				# pretty-print using enscript
alias print='/usr/bin/lp -o nobanner -d $LPDEST'            				# assumes LPDEST is defined (default printer)
alias ps='ps auxf'
alias p_='for ((n=0;n<1;n++)); do dd if=/dev/urandom count=1 2> /dev/null | uuencode -m -| sed -ne 2p | cut -c-8; done' # creating password
alias :q='exit'
alias q='exit'
alias rcci='svn ci ~/rc/'
alias rcup='~/bin/rc_sync.sh'
alias rd='cd "`pwd -P`"' 								# if in directory containing symlink in path, change to "real" path
alias real_location='readlink -f' 							# get real location of file
alias reboot='sudo /sbin/reboot'
# alias reboot='sudo shutdown -r now'   						# easy shutdown management
alias rgrep='find . \( ! -name .svn -o -prune \) -type f -print0 | xargs -0 grep'	# rgrep: recursive grep without .svn
alias rh='rehash'
alias rmdir='rmdir -v's
alias rm_='rm -iv'
alias root='sudo bash -l'								# generic shortcut for switching to root user depending on system
# alias root='sudo -i'									# generic shortcut for switching to root user depending on system
# alias root='su -'									# generic shortcut for switching to root user depending on system
alias scx='screen -x'
alias sdi='sudo dpkg -i'
alias se='vi ~/.screenrc'
alias sg='sudo geany'
alias shutdown='sudo shutdown -h now'							# proper restart
alias shutdownde='for ((;;)) do pgrep wget ||shutdown -h now; sleep 5; done'		# if download end, shutdown
alias sn='sudo nano'
alias split='split -d'
alias sr='screen -d -RR'
# alias s='sudo'
# alias s_='screen -X screen'; s top; s vi; s man ls;					# start a new command in a new screen window
alias sshdo='ssh -q -t root@localhost -- cd $PWD \&\& sudo'				# an alternative to sudo
alias sus='sudo pm-suspend'
alias svi='sudo vim'
alias tc='tar cfvz'
alias te='tail -50f /var/log/qmail/qmail-send/current | elog'
alias tf='tail -50f /var/log/iptables.log'
alias tm='tail -50f /var/log/messages.log'
alias ts='tail -50f /var/log/auth.log'
alias tweet_='bti'
alias tx='tar xfvz'
alias u='mocp -P && sudo pm-suspend ; sleep 1s && mocp -U && setxkbmap -option terminate:ctrl_alt_bksp && xmodmap .config/caps-esc && ~/.fehbg'	# something is messed up somewhere, dirty fix
alias unpack='/bin/tar -xzvpf'								# uncompress a a Tar file
alias updatefont='fc-cache -v -f'
alias url='tinyurl'
alias urlping="ping -q -c 1 www.google.com|awk -F/ 'END{print $5}'"			# do one ping to URL: good in MRTG gauge graph to monitor connectivity
alias v='zless -N'									# -N means display line numbers (turn off line numbers with -n)
alias ve='vi ~/.vimrc'
alias vi='vim'
alias web='w3m'   									# terminal based web browser
alias which='type -all'
alias win='/media/win'
alias wtf='watch -n 1 w -hs'
alias xee='cat /var/log/Xorg.0.log |grep EE'
alias xevs="xev | grep 'keycode\|button'"						# only show button events for xev
alias xp='xprop | grep "WM_WINDOW_ROLE\|WM_CLASS" && echo "WM_CLASS(STRING) = \"NAME\", \"CLASS\""'
alias x='startx'
alias xww='cat /var/log/Xorg.0.log |grep WW'
alias z='zenity --info --text="You will not believe it, but your command has finished now! :-)" --display :0.0'	# get a desktop notification from the terminal
alias zen='fortune /usr/share/fortune/zen'



##################################################
# Command substitution (for typos)		 #
##################################################

alias findgrep='grepfind'
alias mann='man'
alias moer='more'
alias moew='more'
alias updtae='update'
alias vf='cd'
alias xs='cd'
alias yauort='yaourt'
alias yoaurt='yaourt'
alias youart='yaourt'
alias yuaort='yaourt'
alias yuoart='yaourt'



##################################################
# Computer cleanup				 #
##################################################

alias adobecleanup='sudo rm -fr ~/.adobe && sudo rm -fr ~/.macromedia && sudo rm -fr /root/.adobe && sudo rm -fr /root/.macromedia'
alias bleachbitcleanup='sudo bleachbit --clean --preset'
alias cachecleanup='sudo rm -fr /root/.cache/* && sudo rm -fr ~/.cache/*'				# cleanup cache
alias cleanup="sudo apt-get -y autoclean && sudo apt-get -y autoremove && sudo apt-get -y clean && sudo apt-get -y remove && sudo aptitude -y purge `dpkg --get-selections | grep deinstall | awk '{print $1}'` && sudo deborphan | xargs sudo apt-get -y remove --purge && sudo bleachbit --clean --preset && find ~ -type f -name ".DS_Store" -exec rm {} \; && find ~ -type f -name "Thumbs.db" -exec rm {} \; && find ~ -type f -regex ".*~" -exec rm {} \; && sudo rm -rvf ~/.adobe ~/.adobe/Acrobat/*/Cache/ ~/.adobe/Acrobat/*/Preferences/reader_prefs ~/.adobe/Flash_Player/AssetCache/ ~/.amsn/*/*/cache/ ~/.amsn/*/logs/ ~/.amsn/*/voiceclips/ ~/.amsn/*/webcam/ ~/.aMule/logfile ~/.aMule/logfile.bak ~/.aMule/Temp/ ~/.azureus/active/*.bak ~/.azureus/ipfilter.cache ~/.azureus/*.log ~/.azureus/logs/ ~/.azureus/tmp/ ~/.bash_history ~/.beagle/Indexes/ ~/.beagle/Log/ ~/.beagle/TextCache/ ~/.cache/ ~/.cache/* ~/.cache/audacious/thumbs/ ~/.cache/chromium/ ~/.cache/gedit/gedit-metadata.xml ~/.cache/google-chrome/ ~/.cache/vlc/ ~/.compiz/session/ ~/.config/audacious/log ~/.config/audacious/playlist.xspf ~/.config/chromium/Default/Bookmarks.bak ~/.config/chromium/Default/Cookies ~/.config/chromium/Default/Current\ Session ~/.config/chromium/Default/Current\ Tabs ~/.config/chromium/Default/databases/Databases.db ~/.config/chromium/Default/databases/http*/ ~/.config/chromium/Default/Extension\ Cookies ~/.config/chromium/Default/Favicons/ ~/.config/chromium/Default/*History* ~/.config/chromium/Default/*History*/ ~/.config/chromium/Default/*-journal ~/.config/chromium/Default/Last\ Session ~/.config/chromium/Default/Last\ Tabs ~/.config/chromium/Default/Local\ Storage/*localstorage ~/.config/chromium/Default/Thumbnails* ~/.config/chromium/Default/Top\ Sites ~/.config/chromium/Default/Visited\ Links ~/.config/chromium/Default/Web\ Data/chrome.autofill ~/.config/chromium/Default/Web\ Data/chrome.keywords ~/.config/chromium/Local\ State/HostReferralList.json ~/.config/chromium/Local\ State/StartupDNSPrefetchList.json ~/.config/compiz/ ~/.config/emesene*/*/cache/ ~/.config/emesene*/*/log* ~/.config/emesene*/*/logs/ ~/.config/google-chrome/Default/Cookies ~/.config/google-chrome/Default/Current\ Session ~/.config/google-chrome/Default/Current\ Tabs ~/.config/google-chrome/Default/databases/Databases.db ~/.config/google-chrome/Default/databases/http*/ ~/.config/google-chrome/Default/Extension\ Cookies ~/.config/google-chrome/Default/Favicons/ ~/.config/google-chrome/Default/*History* ~/.config/google-chrome/Default/History/ ~/.config/google-chrome/Default/Last\ Session ~/.config/google-chrome/Default/Last\ Tabs ~/.config/google-chrome/Default/Local\ Storage/http*localstorage ~/.config/google-chrome/Default/Preferences/dns_prefetching.json ~/.config/google-chrome/Default/Thumbnails* ~/.config/google-chrome/Default/Top\ Sites ~/.config/google-chrome/Default/Visited\ Links ~/.config/google-chrome/Default/Web\ Data/chrome.autofill ~/.config/google-chrome/Default/Web\ Data/chrome.keywords ~/.config/google-chrome/Local\ State/HostReferralList.json ~/.config/google-chrome/Local\ State/StartupDNSPrefetchList.json ~/.config/gpodder/cache/ ~/.config/menus/*.menu.undo-* ~/.config/real/rpcookies.txt ~/.config/Screenlets/*.log ~/.config/transmission/blocklists/ ~/.config/transmission/resume/ ~/.easytag/easytag.log ~/.elinks/cookies ~/.elinks/*hist /etc/apt/sources.list.d/* ~/.evolution/cache/ ~/.exaile/cache/ ~/.exaile/covers/ ~/.exaile/exaile.log ~/.exaile/podcasts/ ~/.filezilla/recentservers.xml ~/.gconf/apps/gnome-settings/gnome-panel/%gconf.xml ~/.gconf/apps/gnome-settings/gnome-search-tool/%gconf.xml ~/.gftp/cache/ ~/.gftp/gftp.log ~/.gimp-*/tmp/ ~/.gl-117/logfile.txt ~/.gnome2/epiphany/ephy-favicon-cache.xml ~/.gnome2/epiphany/ephy-history.xml ~/.gnome2/epiphany/favicon_cache/ ~/.gnome2/epiphany/mozilla/epiphany/Cache/ ~/.gnome2/epiphany/mozilla/epiphany/cookies* ~/.gnome2/gedit-metadata.xml ~/.gnome2/rhythmbox/jamendo/ ~/.gnome2/rhythmbox/magnatune/ ~/.googleearth/Cache/dbCache.* ~/.googleearth/Temp/ ~/.goutputstream-* ~/.hippo_opensim_viewer/cache/ ~/.hippo_opensim_viewer/logs/ ~/.icedteaplugin/cache/ ~/.java/deployment/cache/ ~/.kde/cache-*/ ~/.kde*/share/apps/gwenview/recent*/*rc ~/.kde/share/apps/kcookiejar/cookies ~/.kde/share/apps/konqueror/autosave/ ~/.kde/share/apps/konqueror/closeditems_saved ~/.kde/share/apps/konqueror/konq_history ~/.kde*/share/apps/RecentDocuments/*.desktop ~/.kde/share/config/konq_history ~/.kde/tmp-*/ ~/.kde/tmp-localhost.localdomain/ ~/.libreoffice/*/*/*/cache/ ~/.libreoffice/*/*/registry/data/org/openoffice/Office/Common.xcu ~/.liferea_*/cache/ ~/.liferea_*/mozilla/liferea/Cache/ ~/.liferea_*/mozilla/liferea/cookies.sqlite ~/.links2/links.his ~/.local/share/gvfs-metadata/*.log ~/.local/share/gvfs-metadata/uuid* ~/.local/share/Trash/ ~/.local/share/Trash/* ~/.luckyBackup/logs/ ~/.luckyBackup/snaps/ ~/.macromedia ~/.macromedia/Flash_Player/ ~/.mc/filepos ~/.mc/history ~/.miro/icon-cache/ ~/.miro/miro-*log* ~/.miro/mozilla/Cache/ ~/.mozilla/default/Cache/ ~/.mozilla/extensions ~/.mozilla/firefox/Crash\ Reports/ ~/.mozilla/firefox/*.default/adblockplus/patterns-backup* ~/.mozilla/firefox/*.default/bookmarkbackups/ ~/.mozilla/firefox/*.default/Cache/ ~/.mozilla/firefox/*.default/cookies.* ~/.mozilla/firefox/*.default/downloads.sqlite ~/.mozilla/firefox/*.default/formhistory.sqlite ~/.mozilla/firefox/*.default/history.dat ~/.mozilla/firefox/*.default/minidumps/ ~/.mozilla/firefox/*.default/mozilla-media-cache/ ~/.mozilla/firefox/*.default/OfflineCache/ ~/.mozilla/firefox/*.default/reminderfox/*.bak* ~/.mozilla/firefox/*.default/sessionstore.* ~/.mozilla/firefox/*.default/startupCache/ ~/.mozilla/firefox/*.default/webappsstore.sqlite ~/.mozilla/seamonkey/*/Cache/ ~/.mozilla/seamonkey/*.default/cookies.sqlite ~/.mozilla/seamonkey/*.default/downloads.sqlite ~/.mozilla/seamonkey/*.default/urlbarhistory.sqlite ~/.mozilla/*/*.slt/chatzilla/logs/*log ~/.mozilla/*/*.slt/cookies.txt ~/.mozilla/*/*.slt/history.dat ~/.mozilla-thunderbird/*.default/signons.txt ~/.nautilus/metafiles/*/*.xml ~/.nautilus/saved-session-?????? ~/.nexuiz/data/dlcache/ ~/.ntrc_*/cookies.txt ~/.ntrc_*/history* ~/.openoffice.org/*/*/*/cache/ ~/.openoffice.org/*/*/registry/data/org/openoffice/Office/Common.xcu ~/.opera/*cache*/ ~/.opera/cookies4.dat ~/.opera/download.dat ~/.opera/global.dat ~/.opera/*history* ~/.opera/icons/ ~/.opera/pstorage/ ~/.opera/sessions/ ~/.opera/temporary_downloads/ ~/.opera/thumbnails/ ~/.opera/vlink4.dat ~/.opera/vps/????/md.dat ~/.purple/icons/ ~/.purple/logs/ ~/.recently-used.xbel ~/.recoll/xapiandb/ /root/.adobe /root/.cache/* /root/.local/share/Trash/* /root/.macromedia /root/.thumbnails/* /root/.Trash ~/.secondlife/cache/ ~/.secondlife/logs/ ~/.Skype/*/chatmsg[0-9]*.dbb ~/.Skype/*/chatsync/*/*.dat ~/.sw35/swiftweasel/*/Cache/ ~/.synaptic/log/ ~/.thumbnails/ ~/.thumbnails/* ~/.thunderbird/*.default/Cache/ ~/.thunderbird/*.default/cookies.sqlite ~/.thunderbird/*.default/signons.sqlite ~/.thunderbird/*.default/signons.txt ~/.thunderbird/default/*.slt/Cache/ ~/.thunderbird/default/*.slt/cookies.sqlite ~/.thunderbird/default/*.slt/signons3.txt ~/.thunderbird/default/*.slt/signons.sqlite ~/.thunderbird/default/*.slt/signons.txt ~/.thunderbird/Profiles/*.default/Cache/ ~/.thunderbird/Profiles/*.default/cookies.sqlite ~/.thunderbird/Profiles/*.default/signons.sqlite ~/.Trash ~/.tremulous/servercache.dat /var/backups/ /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/tmp/ ~/.viminfo ~/.wine/drive_c/winetrickstmp/ ~/.winetrickscache/ ~/.xbmc/addons/Navi-X/cache/images/* ~/.xbmc/addons/packages/* ~/xbmc*.log ~/.xbmc/userdata/Database/Textures* ~/.xbmc/userdata/Thumbnails/* ~/.xchat2/logs/*log ~/.xchat2/scrollback/ ~/.xchat2/xchatlogs/*log ~/.xine/catalog.cache ~/.xsession-errors ~/.xsession-errors.old"
alias configpurge="sudo aptitude -y purge `dpkg --get-selections | grep deinstall | awk '{print $1}'`"	# purge configuration files of removed packages on debian systems
alias kernelcleanup="dpkg -l 'linux-*' | sed '/^ii/!d;/'"$(uname -r | sed "s/\(.*\)-\([^0-9]\+\)/\1/")"'/d;s/^[^ ]* [^ ]* \([^ ]*\).*/\1/;/[0-9]/!d' | xargs sudo apt-get -y purge"											# remove all unused Linux Kernel headers, images & modules
alias orphaned='sudo deborphan | xargs sudo apt-get -y remove --purge'
alias thumbnailcleanup='sudo rm -fr /root/.thumbnails/* && sudo rm -fr ~/.thumbnails/*'
alias tp='trash-put'											# sends files to trash instead of perm deleting w/rm
alias trash='sudo rm -fr ~/.local/share/Trash/* && sudo rm -fr /root/.local/share/Trash/* && sudo rm -fr /root/.Trash && sudo rm -fr ~/.Trash'



##################################################
# DD substitution				 #
##################################################

# alias backup-sda='sudo dd if=/dev/sda of=/dev/hda bs=64k conv=notrunc,noerror'	# to backup the existing drive to ???
# alias backup-sdb='sudo dd if=/dev/sdb of=/dev/hda bs=64k conv=notrunc,noerror'	# to backup the existing drive to ???
# alias backup-sdc='sudo dd if=/dev/sdc of=/dev/hda bs=64k conv=notrunc,noerror'	# to backup the existing drive to ???
# alias backup-sdd='sudo dd if=/dev/sdd of=/dev/hda bs=64k conv=notrunc,noerror'	# to backup the existing drive to ???
# alias backup-sde='sudo dd if=/dev/sde of=/dev/hda bs=64k conv=notrunc,noerror'	# to backup the existing drive to ???
# alias backup-sdf='sudo dd if=/dev/sdf of=/dev/hda bs=64k conv=notrunc,noerror'	# to backup the existing drive to ???
# alias backup-sdg='sudo dd if=/dev/sdg of=/dev/hda bs=64k conv=notrunc,noerror'	# to backup the existing drive to ???
# alias cdcopy='dd if=/dev/cdrom of=cd.iso'						# to backup a cd from a cdrom drive to an ISO
# alias dd-sda-full='sudo dd if=/dev/urandom of=/dev/sda bs=8b conv=notrunc,noerror'	# to wipe hard drive with random data option (1)
# alias dd-sda-r='sudo dd if=/dev/urandom of=/dev/sda bs=102400'			# to wipe hard drive with random data option (2)
# alias dd-sda='sudo dd if=/dev/zero of=/dev/sda conv=notrunc'				# to wipe hard drive with zero
# alias dd-sdb-full='sudo dd if=/dev/urandom of=/dev/sdb bs=8b conv=notrunc,noerror'	# to wipe hard drive with random data option (1)
# alias dd-sdb-r='sudo dd if=/dev/urandom of=/dev/sdb bs=102400'			# to wipe hard drive with random data option (2)
# alias dd-sdb='sudo dd if=/dev/zero of=/dev/sdb conv=notrunc'				# to wipe hard drive with zero
# alias dd-sdc-full='sudo dd if=/dev/urandom of=/dev/sdc bs=8b conv=notrunc,noerror'	# to wipe hard drive with random data option (1)
# alias dd-sdc-r='sudo dd if=/dev/urandom of=/dev/sdc bs=102400'			# to wipe hard drive with random data option (2)
# alias dd-sdc='sudo dd if=/dev/zero of=/dev/sdc conv=notrunc'				# to wipe hard drive with zero
# alias dd-sdd-full='sudo dd if=/dev/urandom of=/dev/sdd bs=8b conv=notrunc,noerror'	# to wipe hard drive with random data option (1)
# alias dd-sdd-r='sudo dd if=/dev/urandom of=/dev/sdd bs=102400'			# to wipe hard drive with random data option (2)
# alias dd-sdd='sudo dd if=/dev/zero of=/dev/sdd conv=notrunc'				# to wipe hard drive with zero
# alias dd-sde-full='sudo dd if=/dev/urandom of=/dev/sde bs=8b conv=notrunc,noerror'	# to wipe hard drive with random data option (1)
# alias dd-sde-r='sudo dd if=/dev/urandom of=/dev/sde bs=102400'			# to wipe hard drive with random data option (2)
# alias dd-sde='sudo dd if=/dev/zero of=/dev/sde conv=notrunc'				# to wipe hard drive with zero
# alias dd-sdf-full='sudo dd if=/dev/urandom of=/dev/sdf bs=8b conv=notrunc,noerror'	# to wipe hard drive with random data option (1)
# alias dd-sdf-r='sudo dd if=/dev/urandom of=/dev/sdf bs=102400'			# to wipe hard drive with random data option (2)
# alias dd-sdf='sudo dd if=/dev/zero of=/dev/sdf conv=notrunc'				# to wipe hard drive with zero
# alias dd-sdg-full='sudo dd if=/dev/urandom of=/dev/sdg bs=8b conv=notrunc,noerror'	# to wipe hard drive with random data option (1)
# alias dd-sdg-r='sudo dd if=/dev/urandom of=/dev/sdg bs=102400'			# to wipe hard drive with random data option (2)
# alias dd-sdg='sudo dd if=/dev/zero of=/dev/sdg conv=notrunc'				# to wipe hard drive with zero
# alias diskcopy='dd if=/dev/dvd of=disk.iso'						# to backup the disc (cd/dvd/whatever) to an ISO
# alias floppycopy='dd if=/dev/fd0 of=floppy.image'					# to duplicate a floppy disk to hard drive image file
# alias partitioncopy='sudo dd if=/dev/sda1 of=/dev/sda2 bs=4096 conv=notrunc,noerror'	# to duplicate one hard disk partition to another
# alias restore-sda='sudo dd if=/dev/hda of=/dev/sda bs=64k conv=notrunc,noerror'	# to restore from ??? to the existing drive
# alias restore-sdb='sudo dd if=/dev/hda of=/dev/sdb bs=64k conv=notrunc,noerror'	# to restore from ??? to the existing drive
# alias restore-sdc='sudo dd if=/dev/hda of=/dev/sdc bs=64k conv=notrunc,noerror'	# to restore from ??? to the existing drive
# alias restore-sdd='sudo dd if=/dev/hda of=/dev/sdd bs=64k conv=notrunc,noerror'	# to restore from ??? to the existing drive
# alias restore-sde='sudo dd if=/dev/hda of=/dev/sde bs=64k conv=notrunc,noerror'	# to restore from ??? to the existing drive
# alias restore-sdf='sudo dd if=/dev/hda of=/dev/sdf bs=64k conv=notrunc,noerror'	# to restore from ??? to the existing drive
# alias restore-sdg='sudo dd if=/dev/hda of=/dev/sdg bs=64k conv=notrunc,noerror'	# to restore from ??? to the existing drive
# alias scsicopy='sudo dd if=/dev/scd0 of=cd.iso'					# if cdrom is scsi}



###### DD substitution using PV to show progress
# requires: sudo apt-get install pv
alias backup-sda='sudo pv /dev/sda | dd of=/dev/hda bs=64k conv=notrunc,noerror'	# to backup the existing drive to ???
alias backup-sdb='sudo pv /dev/sdb | dd of=/dev/hda bs=64k conv=notrunc,noerror'	# to backup the existing drive to ???
alias backup-sdc='sudo pv /dev/sdc | dd of=/dev/hda bs=64k conv=notrunc,noerror'	# to backup the existing drive to ???
alias backup-sdd='sudo pv /dev/sdd | dd of=/dev/hda bs=64k conv=notrunc,noerror'	# to backup the existing drive to ???
alias backup-sde='sudo pv /dev/sde | dd of=/dev/hda bs=64k conv=notrunc,noerror'	# to backup the existing drive to ???
alias backup-sdf='sudo pv /dev/sdf | dd of=/dev/hda bs=64k conv=notrunc,noerror'	# to backup the existing drive to ???
alias backup-sdg='sudo pv /dev/sdg | dd of=/dev/hda bs=64k conv=notrunc,noerror'	# to backup the existing drive to ???
alias cdcopy='pv /dev/cdrom | dd of=cd.iso'						# to backup a cd from a cdrom drive to an ISO
alias dd-sda-full='sudo pv /dev/urandom | dd of=/dev/sda bs=8b conv=notrunc,noerror'	# to wipe hard drive with random data option (1)
alias dd-sda-r='sudo pv /dev/urandom | dd of=/dev/sda bs=102400'			# to wipe hard drive with random data option (2)
alias dd-sda='sudo pv /dev/zero | dd of=/dev/sda conv=notrunc'				# to wipe hard drive with zero
alias dd-sdb-full='sudo pv /dev/urandom | dd of=/dev/sdb bs=8b conv=notrunc,noerror'	# to wipe hard drive with random data option (1)
alias dd-sdb-r='sudo pv /dev/urandom | dd of=/dev/sdb bs=102400'			# to wipe hard drive with random data option (2)
alias dd-sdb='sudo pv /dev/zero | dd of=/dev/sdb conv=notrunc'				# to wipe hard drive with zero
alias dd-sdc-full='sudo pv /dev/urandom | dd of=/dev/sdc bs=8b conv=notrunc,noerror'	# to wipe hard drive with random data option (1)
alias dd-sdc-r='sudo pv /dev/urandom | dd of=/dev/sdc bs=102400'			# to wipe hard drive with random data option (2)
alias dd-sdc='sudo pv /dev/zero | dd of=/dev/sdc conv=notrunc'				# to wipe hard drive with zero
alias dd-sdd-full='sudo pv /dev/urandom | dd of=/dev/sdd bs=8b conv=notrunc,noerror'	# to wipe hard drive with random data option (1)
alias dd-sdd-r='sudo pv /dev/urandom | dd of=/dev/sdd bs=102400'			# to wipe hard drive with random data option (2)
alias dd-sdd='sudo pv /dev/zero | dd of=/dev/sdd conv=notrunc'				# to wipe hard drive with zero
alias dd-sde-full='sudo pv /dev/urandom | dd of=/dev/sde bs=8b conv=notrunc,noerror'	# to wipe hard drive with random data option (1)
alias dd-sde-r='sudo pv /dev/urandom | dd of=/dev/sde bs=102400'			# to wipe hard drive with random data option (2)
alias dd-sde='sudo pv /dev/zero | dd of=/dev/sde conv=notrunc'				# to wipe hard drive with zero
alias dd-sdf-full='sudo pv /dev/urandom | dd of=/dev/sdf bs=8b conv=notrunc,noerror'	# to wipe hard drive with random data option (1)
alias dd-sdf-r='sudo pv /dev/urandom | dd of=/dev/sdf bs=102400'			# to wipe hard drive with random data option (2)
alias dd-sdf='sudo pv /dev/zero | dd of=/dev/sdf conv=notrunc'				# to wipe hard drive with zero
alias dd-sdg-full='sudo pv /dev/urandom | dd of=/dev/sdg bs=8b conv=notrunc,noerror'	# to wipe hard drive with random data option (1)
alias dd-sdg-r='sudo pv /dev/urandom | dd of=/dev/sdg bs=102400'			# to wipe hard drive with random data option (2)
alias dd-sdg='sudo pv /dev/zero | dd of=/dev/sdg conv=notrunc'				# to wipe hard drive with zero
alias diskcopy='pv /dev/dvd | dd of=disk.iso'						# to backup the disc (cd/dvd/whatever) to an ISO
alias floppycopy='pv /dev/fd0 | dd of=floppy.image'					# to duplicate a floppy disk to hard drive image file
alias partitioncopy='sudo pv /dev/sda1 | dd of=/dev/sda2 bs=4096 conv=notrunc,noerror'	# to duplicate one hard disk partition to another
alias restore-sda='sudo pv /dev/hda | dd of=/dev/sda bs=64k conv=notrunc,noerror'	# to restore from ??? to the existing drive
alias restore-sdb='sudo pv /dev/hda | dd of=/dev/sdb bs=64k conv=notrunc,noerror'	# to restore from ??? to the existing drive
alias restore-sdc='sudo pv /dev/hda | dd of=/dev/sdc bs=64k conv=notrunc,noerror'	# to restore from ??? to the existing drive
alias restore-sdd='sudo pv /dev/hda | dd of=/dev/sdd bs=64k conv=notrunc,noerror'	# to restore from ??? to the existing drive
alias restore-sde='sudo pv /dev/hda | dd of=/dev/sde bs=64k conv=notrunc,noerror'	# to restore from ??? to the existing drive
alias restore-sdf='sudo pv /dev/hda | dd of=/dev/sdf bs=64k conv=notrunc,noerror'	# to restore from ??? to the existing drive
alias restore-sdg='sudo pv /dev/hda | dd of=/dev/sdg bs=64k conv=notrunc,noerror'	# to restore from ??? to the existing drive
alias scsicopy='sudo pv /dev/scd0 | dd of=cd.iso'					# if cdrom is scsi}



##################################################
# Defragmenting and Fragmentation-Checking	 #
# Tools						 #
##################################################

alias defrag-home='defrag ~'			# uses 'defrag' function
alias defrag-root='defrag /root'		# uses 'defrag' function
alias defrag-system='defrag /'			# uses 'defrag' function
alias defrag2-home='defrag2 ~'			# uses 'defrag2' function
alias defrag2-root='defrag2 /root'		# uses 'defrag2' function
alias defrag2-system='defrag2 /'		# uses 'defrag2' function
alias fragcheck-home='fragcheck ~'		# uses 'fragcheck' function
alias fragcheck-root='fragcheck /root'		# uses 'fragcheck' function
alias fragcheck-system='fragcheck /'		# uses 'fragcheck' function
alias fragcheck2-home='fragcheck2 ~'		# uses 'fragcheck2' function
alias fragcheck2-root='fragcheck2 /root'	# uses 'fragcheck2' function
alias fragcheck2-system='fragcheck2 /'		# uses 'fragcheck2' function



##################################################
# Directory shortcuts				 #
##################################################

alias back='cd $OLDPWD'
alias backgrounds='cd ~/Pictures/Backgrounds'
alias backups='cd ~/Backups'
alias books='cd ~/eBooks'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias .....='cd ../../../..'
alias ......='cd ../../../../..'
alias documents='cd ~/Documents'
alias downloads='cd ~/Downloads'
alias drive-c='cd ~/.wine/drive_c'
alias dropbox='cd ~/Dropbox'
alias home='cd ~/'
alias images='cd ~/Images'
alias localhost='cd /var/www'
alias movies='cd ~/Videos'
alias music='cd ~/Music'
alias nautilus-scripts='cd ~/.gnome2/nautilus-scripts'
alias nemo-scripts='cd ~/.gnome2/nemo-scripts'
alias packages='cd ~/Packages'
alias packets='cd ~/.packets'
alias pictures='cd ~/Pictures'
alias ppc='cd ~/PPC'
alias public='cd ~/Public'
alias temp='cd ~/Temp'
alias test='cd ~/.test'
alias torrents='cd ~/Torrents'
alias ubuntu-texts='cd ~/Documents/"Ubuntu Texts"'
alias videos='cd ~/Videos'
alias webdesign='cd ~/Web/Design'
alias whereami='display_info'



##################################################
# Espeak commands				 #
##################################################

alias espeak-file='espeak -s 150 -f'
alias espeak-us='espeak -v en-us -s 150'
alias espeak-wav='espeak -s 150 -w voice.wav'
alias espeak-wav-file='espeak -s 150 -w voice.wav -f'



##################################################
# Extundelete stuff from ext3/ext4 filesystems	 #
##################################################

alias extundelete-d='sudo extundelete "$1" --restore-directory "$2"'		# restore all files possible from specified dir.  ("$2" = path/to/directory)
alias extundelete-f='sudo extundelete "$1" --restore-files "$2"'		# restore list of files (use to restore single file) ("$2" = filename)
alias extundelete-r='sudo extundelete "$1" --restore-all'			# restore all files possible to undelete
alias extundelete-sda='sudo extundelete /dev/sda --restore-all'			# restore all files possible to undelete
alias extundelete-sda-d='sudo extundelete /dev/sda --restore-directory "$1"'	# restore all files possible from specified dir.  ("$1" = path/to/directory)
alias extundelete-sda-f='sudo extundelete /dev/sda --restore-files "$1"'	# restore list of files (use to restore single file) ("$1" = filename)
alias extundelete-sdb='sudo extundelete /dev/sdb --restore-all'			# restore all files possible to undelete
alias extundelete-sdb-d='sudo extundelete /dev/sdb --restore-directory "$1"'	# restore all files possible from specified dir.  ("$1" = path/to/directory)
alias extundelete-sdb-f='sudo extundelete /dev/sdb --restore-files "$1"'	# restore list of files (use to restore single file) ("$1" = filename)
alias extundelete-sdc='sudo extundelete /dev/sdc --restore-all'			# restore all files possible to undelete
alias extundelete-sdc-d='sudo extundelete /dev/sdc --restore-directory "$1"'	# restore all files possible from specified dir.  ("$1" = path/to/directory)
alias extundelete-sdc-f='sudo extundelete /dev/sdc --restore-files "$1"'	# restore list of files (use to restore single file) ("$1" = filename)
alias extundelete-sdd='sudo extundelete /dev/sdd --restore-all'			# restore all files possible to undelete
alias extundelete-sdd-d='sudo extundelete /dev/sdd --restore-directory "$1"'	# restore all files possible from specified dir.  ("$1" = path/to/directory)
alias extundelete-sdd-f='sudo extundelete /dev/sdd --restore-files "$1"'	# restore list of files (use to restore single file) ("$1" = filename)
alias extundelete-sde='sudo extundelete /dev/sde --restore-all'			# restore all files possible to undelete
alias extundelete-sde-d='sudo extundelete /dev/sde --restore-directory "$1"'	# restore all files possible from specified dir.  ("$1" = path/to/directory)
alias extundelete-sde-f='sudo extundelete /dev/sde --restore-files "$1"'	# restore list of files (use to restore single file) ("$1" = filename)
alias extundelete-sdf='sudo extundelete /dev/sdf --restore-all'			# restore all files possible to undelete
alias extundelete-sdf-d='sudo extundelete /dev/sdf --restore-directory "$1"'	# restore all files possible from specified dir.  ("$1" = path/to/directory)
alias extundelete-sdf-f='sudo extundelete /dev/sdf --restore-files "$1"'	# restore list of files (use to restore single file) ("$1" = filename)
alias extundelete-sdg='sudo extundelete /dev/sdg --restore-all'			# restore all files possible to undelete
alias extundelete-sdg-d='sudo extundelete /dev/sdg --restore-directory "$1"'	# restore all files possible from specified dir.  ("$1" = path/to/directory)
alias extundelete-sdg-f='sudo extundelete /dev/sdg --restore-files "$1"'	# restore list of files (use to restore single file) ("$1" = filename)



##################################################
# Git stuff					 #
##################################################

alias gitouch='find . \( -type d -empty \) -and \( -not -regex ./\.git.* \) -exec touch {}/.gitignore \;'
alias gitup='git pull'
alias gitci='git commit -a -m'
alias gitco='git clone'
alias gita='git add'
alias gitb='git branch'
alias gitc='git checkout'



##################################################
# Hardware Shortcuts				 #
##################################################

alias 0='amixer set PCM 0'
alias -- -='amixer set PCM 2-'
alias +='amixer set PCM 2+'
alias blankcd='cdrecord -v dev=/dev/cdrom blank=fast gracetime=3'
alias blankdvd='cdrecord -v dev=/dev/dvd blank=fast gracetime=3'
alias blueoff='sudo /etc/rc.d/bluetooth stop'
alias blueon='sudo /etc/rc.d/bluetooth start'
alias blueres='sudo /etc/rc.d/bluetooth restart'
alias brand='growisofs -Z /dev/cdrw -v -l -R -J -joliet-long'
alias burnaudiocd='mkdir ./temp && for i in *.[Mm][Pp]3;do mpg123 -w "./temp/${i%%.*}.wav" "$i";done;cdrecord -pad ./temp/* && rm -r ./temp'	# burn a directory of mp3s to an audio cd
alias cdc='eject -t /dev/cdrecorder'
alias cdo='eject /dev/cdrecorder'
alias cruzer='mount /media/cruzer'
alias dvdc='eject -t /dev/dvd'
alias dvdo='eject /dev/dvd'
alias ipod='mount /media/ipod && cd /media/ipod'
alias keject='sudo eject Kindle'						# ejects Kindle devices but keeps it charging (simple 'eject' doesn't work)
alias kingston='mount /media/kingston && cd /media/kingston'
alias laptop_display='sudo cat /proc/acpi/video/VGA/LCD/brightness'		# set laptop display brightness	(path may vary depending on laptop model
alias laptop_displays='echo <percentage> > /proc/acpi/video/VGA/LCD/brightness'	# to discover the possible values for your display
alias mountcd='sudo mount -t is09660 /dev/sr0 /media/cdrom'
alias mountedinfo='df -hT'
alias mountiso='sudo mount ${1} ${2} -t iso9660 -o ro,loop=/dev/loop0'
alias mountwin='mount -t ntfs /dev/sda1 /media/win'
alias mp3='mount /media/mp3 && cd /media/mp3'
alias playm='for i in *.mp3; do play $i; done'
alias playo='for i in *.ogg; do play $i; done'
alias playw='for i in *.wav; do play $i; done'
alias scan='scanimage -L'
alias sd='mount /media/sd'
alias ucruzer='umount /media/cruzer'
alias uipod='umount /media/ipod'
alias ukingston='umount /media/kingston'
alias umountiso='sudo umount /media/iso'
alias ump3='umount /media/mp3'
alias usd='umount /media/sd'
alias uverbatim='umount /media/verbatim'
alias verbatim='mount /media/verbatim && cd /media/verbatim'



##################################################
# Information					 #
##################################################

alias acpi='acpi -V'									# shows all of acpi's info (battery, adapter, thermal, cooling)
alias battery='acpi -bi'								# find large files in current directory
alias big='function BIG() { find . -size +${1}M -ls; }; BIG $1'				# find large files in current directory
alias biggest='BLOCKSIZE=1048576; du -x | sort -nr | head -10'				# show biggest directories
alias biggest_user="ac -p | sort -nk 2 | awk '/total/{print x};{x=$1}"			# show which user has the most accumulated login time
alias boothistory='for wtmp in `dir -t /var/log/wtmp*`; do last reboot -f $wtmp; done | less'
alias charcount='wc -c $1'								# count number of characters in text file
alias codename='lsb_release -cs | sed "s/^./\u&/"'					# Linux version detail - just codename (Natty, Oneiric, etc)
alias color1='sh ~/.scripts/termcolor1'   						# displays colorset 1
alias color2='sh ~/.scripts/termcolor2'   						# displays colerset 2
alias color3='sh ~/.scripts/termcolor3'   						# displays colorset 3
alias cooling='acpi -c'									# shows cooling for processors
alias counts='sort | uniq -c | sort -nr'						# a nice command for summarising repeated information
alias cpu_hogs='ps wwaxr -o pid,stat,%cpu,time,command | head -10'			# to find CPU hogs
alias cpus='grep -c ^processor /proc/cpuinfo'						# number of CPU's in a system
alias cpus_='grep "processor" /proc/cpuinfo | wc -l'					# number of CPU's in a system
alias cpu='sudo dmidecode | grep Core'							# CPU info in a system
alias cputemp='while sleep 1; do acpi -t | osd_cat -p bottom; done &'			# to get the CPU temperature continuously on the desktop
alias ctemp='sensors -f && sensors'							# to get the computer temperature in Fahrenheit and Celcius
alias df='df -h -x tmpfs -x usbfs'							# displays global disk usage by partition, excluding supermounted devices
alias directorydiskusage='du -s -k -c * | sort -rn'
alias dir='ls --color=auto --format=vertical'
alias diskwho='sudo iotop'
alias distro='lsb_release -is'								# Linux distro version (Ubuntu, Linux Mint, Debian, Fedora, etc)
alias distro_='cat /etc/lsb-release | grep DISTRIB_ID | cut -d '=' -f 2'		# Linux distro version (Ubuntu, Linux Mint, Debian, Fedora, etc)
alias distro_ver='lsb_release -rs'							# Linux version detail - just codename version (11.04, 11.10, etc)
alias distro_vers='lsb_release -ds'							# Linux distro and version details (Ubuntu 11.04)
alias dmidecode='sudo dmidecode --type 17 | more'					# check RAM sed and type in Linux
alias ducks='sudo ls -A | grep -v -e '\''^\.\.$'\'' |xargs -i du -ks {} |sort -rn |head -16 | awk '\''{print $2}'\'' | xargs -i du -hs {}'	# useful alias to browse your filesystem for heavy usage quickly						# to show processes reading/writing to disk
alias du='du -h --max-depth=1'								# displays disk usage by directory, in human readable format
alias dush='du -sm *|sort -n|tail'							# easily find megabyte eating files or directories
alias env2='for _a in {A..Z} {a..z};do _z=\${!${_a}*};for _i in `eval echo "${_z}"`;do echo -e "$_i: ${!_i}";done;done|cat -Tsv'	# print all environment variables, including hidden ones
alias ffind='sudo find / -name $1'
alias free='free -m'									# RAM and SWAP detail in MBs
alias freqwatch='watch --interval 1 "cat /proc/acpi/thermal_zone/THRM/*; cat /proc/cpuinfo | grep MHz; cat /proc/acpi/processor/*/throttling"'  # monitor cpu freq and temperature
alias hardware='sudo lshw -html > hardware.html'					# overview of the hardware in the computer
# alias hgrep='history | grep --color=always'						# search commands history
alias hiddenpnps='unhide (proc|sys|brute)'						# forensic tool to find hidden processes and ports
alias hogc='ps -e -o %cpu,pid,ppid,user,cmd | sort -nr | head'				# display the processes that are using the most CPU time and memory
alias hogm='ps -e -o %mem,pid,ppid,user,cmd | sort -nr | head'				# display the processes that are using the most CPU time and memory
alias la_='ls -Al'									# show hidden files
alias l?='cat ~/technical/tips/ls'
alias lc='ls -ltcr'       								# sort by and show change time, most recent last
alias ldir='ls -lhA |grep ^d'
alias ld='ls -ltr' 									# sort by date
alias lfiles='ls -lhA |grep ^-'
alias lf="ls -Alh --color | awk '{k=0;for(i=0;i<=8;i++)k+=((substr(\$1,i+2,1)~/[rwx]/)*2^(8-i));if(k)printf(\" %0o \",k);print}'"	# full ls with octal+symbolic permissions
alias lgg='ls --color=always | grep --color=always -i'					# quick case-insenstive partial filename search
alias lh='ls -Al' 									# show hidden files
alias lh='ls -lAtrh' 									# sort by date and human readable
alias libpath='echo -e ${LD_LIBRARY_PATH//:/\\n}'
alias li='ls -ai1|sort' 								# sort by index number
alias linecount='wc -l $1'								# count number of lines in text file
alias lk='ls -lSr'									# sort by size
alias llllll='ls -FlaXo --color=auto'							# sort the extensions alphabetically; good for winfiles
alias lllll='ls -Fla --full-time -o -Q --color=auto'					# whatever
alias llll='ls -laS --color=auto'							# sort by size
alias lll='ls -Falot --color=auto'							# sort by mod time
alias ll_='ls -l'									# long listing
alias l.='ls -d .[[:alnum:]]* 2> /dev/null || echo "No hidden file here..."'		# list only hidden files
alias l='ls -hF --color'								# quick listing
alias lm_='ls -al |more'    								# pipe through 'more'
alias ln='ln -s'
alias lr='ls -lR'									# recursice ls
alias lrt='ls -lart'									# list files with last modified at the end
alias lsam='ls -am' 									# List files horizontally
alias lsdd='ls -latr'                                 					# sort by date
alias lsd='ls -l | grep "^d"'								# list only directories
alias lsize='ls --sort=size -lhr'							# list by size
alias lsl='ls -lah'                                   					# long list, human-readable
alias ls='ls -hF --color'								# add colors for filetype recognition
alias lsnew='ls -Alh --color=auto --time-style=+%D | grep `date +%D`'
alias lss='ls -shaxSr'                         			       			# sort by size
alias lsss='ls -lrt | grep $1'								# to see something coming into ls output: lss
alias lsx='ls -ax' 									# sort right to left rather then in columns
alias lt_='ls -alt|head -20' 								# 20, all, long listing, modification time
alias lt='ls -ltr'         								# sort by date, most recent last
alias lu='ls -ltur'        								# sort by and show access time, most recent last
alias lx='ls -lXB'									# sort by extension
# alias man='TERMINFO=~/.terminfo TERM=mostlike LESS=C PAGER=less man'			# cool colors for manpages
alias mem_hogs_ps='ps wwaxm -o pid,stat,vsize,rss,time,command | head -10'		# to find memory hogs
alias mem_hogs_top='top -l 1 -o rsize -n 10'						# to find memory hogs
# alias mem='~/.scripts/realmem'							# estimates memory usage
alias mypc="hal-get-property --udi /org/freedesktop/Hal/devices/computer --key 'system.hardware.product'"		# show computer model
alias myps='/bin/ps -u "$USER" -o user,pid,ppid,pcpu,pmem,args|less'			# ps
alias numFiles='echo $(ls -1 | wc -l)'							# numFiles: number of (non-hidden) files in current directory
alias ontime='date -d @$(echo $(($(date +%s)-$(cat /proc/uptime|cut -d. -f1))))'	# knowing when a machine is turned on
alias packagelist_="sudo aptitude search -F %p ~i --disable-columns | sed 's/$/,/' | tr '\n\r' ' ' | sed 's/, $//'"	# list all packages (1-liner)
alias packagelist="sudo aptitude search -F %p ~i --disable-columns"			# show list of all packages (columns)
# alias packagelist='sudo dpkg --get-selections'					# show llist of all packages (columns)
alias phonesearch='grep '[0-9]\{3\}-[0-9]\{4\}' "$1"'					# search phone #'s in file (requires XXX-XXX-XXXX format)
alias processbycpuusage="ps -e -o pcpu,cpu,nice,state,cputime,args --sort pcpu | sed '/^ 0.0 /d'"
alias processbymemusage='ps -e -o rss=,args= | sort -b -k1,1n | pr -TW$COLUMNS'
alias processtree='ps -e -o pid,args --forest'
alias pss='ps -ef | grep $1'								# to check a process is running in a box with a heavy load: pss
alias rcommand='ls /usr/bin | shuf -n 1'						# get a random command
# alias rcommand='man $(ls /usr/bin | shuf -n 1)'					# get a random command
alias sete='set|sed -n "/^`declare -F|sed -n "s/^declare -f \(.*\)/\1 ()/p;q"`/q;p"'	# display environment vars only, using set
alias showallaliases='compgen -A alias'							# list bash alias defined in .bash_profile or .bashrc
alias showallfunctions='compgen -A function'						# list bash functions defined in .bash_profile or .bashrc
alias sizeof='du -sh'
alias space='df -h'									# disk space usage
alias sshall='logwatch --service sshd --range all --detail high --print --archives'
alias sshtoday='logwatch --service sshd --range today --detail high --print --archives'
alias superfind='sudo find / ! \( -path /proc -prune -o -path /tmp -prune -o -path /dev -prune -o -path /mnt -prune \) -name'
alias temperature='acpi -tf && acpi -t'							# shows computer temperature, in Fahrenheit and Celsius
alias top20='du -xk | sort -n | tail -20'						# find the 20 biggest directories on the current filesystem
alias top-commands='history | awk "{print $2}" | awk "BEGIN {FS="|"} {print $1}" |sort|uniq -c | sort -rn | head -10'	# show most popular commands
alias topforever='top -l 0 -s 10 -o cpu -n 15'						# continual 'top' listing (every 10 sec) showing top 15 CPU things
alias topten='du -sk $(/bin/ls -A) | sort -rn | head -10'				# displays the top ten biggest folders/files in the current directory
alias top_='xtitle Processes on $HOST && top'						# uses the function 'xtitle'
alias top_processes="watch -n 1 'ps -aux | sort -nrk 4 | head'"				# monitoring which processes most use CPU
alias treefind_="find . | sed 's/[^/]*\//|   /g;s/| *\([^| ]\)/+--- \1/'"		# displays a tree of the arborescence
alias tree='tree -Cs'									# nice alternative to 'ls'
alias unusedkernels="dpkg -l 'linux-*' | sed '/^ii/!d;/'"$(uname -r | sed "s/\(.*\)-\([^0-9]\+\)/\1/")"'/d;s/^[^ ]* [^ ]* \([^ ]*\).*/\1/;/[0-9]/!d'"											# show installed but unused linux headers, image, or modules
alias vdir='ls --color=auto --format=long'
alias ver='cat /etc/lsb-release'							# Ubuntu version details
alias version='sudo apt-show-versions'							# show version
alias whichall='{ command alias; command declare -f; } | command which --read-functions --read-alias -a'		# which alias
alias WHOAMI='getent passwd $(whoami) | cut -f 5 -d: | cut -f 1 -d,'			# prints out what the users name, notifyed in the gecos field is
alias wordcount='wc -w $1'								# count number of words in text file



##################################################
# Information (clock and date stuff)		 #
##################################################

alias am-pm='date +"%p"'								# AM/PM (ex. AM)
alias bdate2="date +'%a %Y-%m-%d %H:%M:%S %z'"						# date command (ex. Sun 2011-01-23 05:39:26 -0500)
alias bdate3='date "+%Y-%m-%d %A    %T %Z"'						# date command (ex. 2011-01-23 Sunday    05:39:23 EST)
alias bdate="date '+%a, %b %d %Y %T %Z'"						# date command (ex. Sun, Jan 23 2011 05:39:13 EST)
alias cal='cal -3' 									# show 3 months by default
alias date_='TZ=$TZ-72 date +%d.%m.%Y'							# solaris: get current date + 72 hours
alias dateformatcodes='date --help | sed -n '/^FORMAT/,/%Z/p''				# alias for seeing date's format codes
alias dateh='date --help|sed "/^ *%a/,/^ *%Z/!d;y/_/!/;s/^ *%\([:a-z]\+\) \+/\1_/gI;s/%/#/g;s/^\([a-y]\|[z:]\+\)_/%%\1_%\1_/I"|while read L;do date "+${L}"|sed y/!#/%%/;done|column -ts_'								# view all date formats, quick reference help alias
alias day='date +%A'									# day of the week (ex. Saturday)
alias DAY='date "+%A" | tr '[a-z]' '[A-Z]''						# day (text) (ex. SATURDAY)
alias day#='date +%d'									# date (numeric) (ex. 22)
alias daysleft='echo "There are $(($(date +%j -d"Dec 31, $(date +%Y)")-$(date +%j))) left in year $(date +%Y)."'	# how many days until the end of the year
alias epochdaysleft="perl -e 'printf qq{%d\n}, time/86400;'"				# perl one-liner to determine number of days since the Unix epoch
alias epochtime='date +%s'								# report number of seconds since the Epoch (ex. 1295779549)
alias month='date +%B'									# month (ex. January)
alias MONTH='date "+%B" | tr '[a-z]' '[A-Z]''						# month (text) (ex. JANUARY)
alias mytime='date +%H:%M:%S'								# shows just the current time (ex. 05:46:05)
alias ntpdate='sudo ntpdate ntp.ubuntu.com pool.ntp.org'				# time synchronisation with NTP (ex. 23 Jan 05:46:29)
alias oclock='read -a A<<<".*.**..*....*** 8 9 5 10 6 0 2 11 7 4";for C in `date +"%H%M"|fold -w1`;do echo "${A:${A[C+1]}:4}";done'   # odd clock
alias onthisday='grep -h -d skip `date +%m/%d` /usr/share/calendar/*'			# on this day
alias onthisday_='firefox http://en.wikipedia.org/wiki/$(date +'%b_%d')'		# what happened on this day in history?
alias secconvert='date -d@1234567890'							# convert seconds to human-readable format (ex. Fri Feb 13 18:31:30 EST 2009)
alias stamp='date "+%Y%m%d%a%H%M"'							# timestamp (ex. 20110123Sun0545)
alias time2='date +"%I:%M"'								# time (hours:minutes) (ex. 05:13)
alias time3='date +"%l:%M %p"'								# time (ex. 5:13 AM)
alias time4='date +"%H:%M"'								# time (hours:minutes) (ex. 05:13)
alias timestamp='date "+%Y%m%dT%H%M%S"'							# timestamp (ex. 20110123T054906)
alias today='date +"%A, %B %-d, %Y"'							# date command (ex. Sunday, January 23, 2011)
alias weeknum='date +%V'								# perl one-liner to get the current week number (ex. 03)



##################################################
# Miscellaneous					 #
##################################################

alias -- --='-;-'
alias -- ---='-;-;-'
alias -- ----='-;-;-;-'
alias -- -----='-;-;-;-;-'
alias ++='+;+'
alias +++='+;+;+'
alias ++++='+;+;+;+'
alias +++++='+;+;+;+;+'
alias 7z_it='7z a -mx=9 -ms=on archive.7z $1'						# create solid archive (best compression) with 7z
alias addrepo='sudo add-apt-repository'							# add a repo to repo .list
alias alert_helper='history|tail -n1|sed -e "s/^\s*[0-9]\+\s*//" -e "s/;\s*alert$//"'	# notified when job run in terminal is done using NotifyOSD
alias alert='notify-send -i gnome-terminal "Finished Terminal Job" "[$?] $(alert_helper)"'	# usage: sleep 5; alert
alias alph='cat "$1" | sort > "$1"'							# alphabetizes a file
alias alsamixer='alsamixer -V all'
alias bashrc-copy-r='sudo cp /root/.bashrc ~/.bashrc'
alias bashrc-copy='sudo cp ~/.bashrc /root/.bashrc'
alias bashrc-cpr='sudo cp ~/.bashrc /root/.bashrc && cp ~/.bashrc ~/Temp && gedit ~/.bashrc && exit'
alias bashrc='gedit ~/.bashrc & exit'
alias bashrc-root='sudo gedit ~/.bashrc & exit'
alias bashrc-temp='cp ~/.bashrc ~/Temp'
alias bbc='lynx -term=vt100 http://news.bbc.co.uk/text_only.stm'
alias bedit='vim ~/.bashrc; source ~/.bashrc'
alias beep='echo -en "\007"'								# ring the bell
alias bgedit='gedit ~/.bashrc; source ~/.bashrc'
alias blipfm="mpg123 `curl -s http://blip.fm/all | sed -e 's#"#\n#g'  | grep mp3$  | xargs`"	# play random music from blip.fm
alias capture='IMAGE="$HOME/Pictures/capture-`date +%Y%m%d%H%M%S`.png"; import -frame $IMAGE; echo "Image saved as $IMAGE"'	# save portion of desktop as image
alias cic='set completion-ignore-case On'						# make tab-completion case-insensitive
alias clisp='clisp -q'
alias commentremove="sed 's/[[:blank:]]*#.*//; /^$/d' "$1""				# this will remove comments that are at the end of lines
alias compiz-replace='compiz --replace'							# refreshes compiz (fixes drag/drop issue, among others)
alias cut80='/usr/bin/cut -c 1-80'							# truncate lines longer than 80 characters (for use in pipes)
alias debrepack='sudo dpkg-repack'							# just an easier-to-remember alias for 'dpkg-repack'
alias differ='sdiff --suppress-common-lines'						# bash alias for sdiff: differ
alias dmregister='lynx http://desmoinesregister.com'
alias dos2unix_='perl -pi -e 's/\r\n/\n/g' *'
alias downNuncompress='wget http://URL/FILE.tar.gz -O- | tar xz'			# download a file and uncompress it while it downloads
# alias downNuncompress='curl http://URL/FILE.tar.gz | tar xz'				# download a file and uncompress it while it downloads
alias du0='du --max-depth=0'
alias du1='du --max-depth=1'
alias ebrc='nano ~/.bashrc'
alias ebrcupdate='source ~/.bashrc'
alias edit='nano'
alias elog='tai64nlocal'
alias encryptall='for f in * ; do [ -f $f ] && openssl enc -aes-256-cbc -salt -in $f -out $f.enc -pass file:/tmp/password-file ; done'	# encrypt every file in current directory with 256-bit AES, retaining original
alias fixmount='sudo e2fsck -f /dev/sda1'						# repair device booting/mounting error (for /dev/sda1)
alias fixopera='rm -r ~/.opera/{mail,lock}'
alias fixres='xrandr --size 1600x1200'      						# reset resolution
alias fix_stty='stty sane'								# restore terminal settings when they get completely screwed up
alias flv2ogg='for i in $(ls *.flv); do ffmpeg2theora -v 6 --optimize $i; done'		# convert all FLV's in a directory to Ogg Theora (video)
alias foldpb='pbpaste | fold -s | pbcopy'						# make text in clipboard wrap so as to not exceed 80 characters
alias funkcje="grep -o '^[a-zA-Z]\{1,\}.(*)' ~/.bashrc"
alias gdbbt='gdb -q -n -ex bt -batch'							# print stack trace of a core file without needing to enter gdb interactively
alias gifted='giftd -d && giFTcurs'
alias gitk='screen -d -m gitk'
alias gmail='sh /$HOME/.scripts/gmail.sh'
alias googlevideo='wget -qO- "VURL" | grep -o "googleplayer.swf?videoUrl\\\x3d\(.\+\)\\\x26thumbnailUrl\\\x3dhttp" | grep -o "http.\+" | sed -e's/%\([0-9A-F][0-9A-F]\)/\\\\\x\1/g' | xargs echo -e | sed 's/.\{22\}$//g' | xargs wget -O "$1"'	# Google video download
alias gsop='gmplayer http://localhost:8909 -prefer-ipv4'
alias head='head -n $((${LINES:-`tput lines 2>/dev/null||echo -n 12`} - 2))'		# alias HEAD for automatic smart output
alias hiresvideo='mplayer -framedrop -vfm ffmpeg -lavdopts lowres=1:fast:skiploopfilter=all'	# play high-res video files on a slow processor
alias image2pdf='convert -adjoin -page A4 *.jpeg multipage.pdf'				# convert images to a multi-page pdf
alias irb='irb --readline -r irb/completion -rubygems'
alias jargon='wget -m http://catb.org/~esr/jargon/html/ -nH --cut-dirs=2 -np -L -P ~/Jargon/'
alias kernbuild='make -j3 && make modules_install && ls -ld ../linux && date'		# compile kernel, install modules, display kernel vers & date
alias kfire='for i in `ps aux | grep [F]irefox `; do echo $i; kill $(($i)); done; '
# alias kfire='kill $(pidof firefox)'
# alias kfire='kill $(ps aux | awk '/firefox/ {print $2}' | tr '\n' ' ')'
alias killall='killall -u $USER -v' 							# only kill our own processes, and also be verbose about it
alias killall_wine='wineserver -k'							# stop all Wine apps and processes
alias lastlog='lastlog | grep -v Never'
alias less='less -Mw'
alias lssd='ps ax | grep -v grep | grep -i firefox | while read pid; do kill "${pid%% *}"; done'
alias lstexfont='ls {/usr/share/texmf-dist/tex/latex/psnfss/*.sty,/usr/share/texmf-dist/tex/latex/pxfonts/*.sty}'
alias lvim="vim -c \"normal '0\""							# open the last file you edited in Vim.
alias makepasswd='makepasswd -minchars 8'
alias make_='xtitle Making $(basename $PWD) ; make'					# uses the function 'xtitle'
alias mencoder-join='mencoder -forceidx -ovc copy -oac copy -o'				# just add: whatever.avi whatever.pt1.avi whatever.pt2.avi ...
alias memlimit='ulimit -v 1000000; $1'							# limit memory usage per script/program
alias mic_record='arecord -q -f cd -r 44100 -c2 -t raw | touch `date +%Y%m%d%H%M`.mp3 | lame -S -x -h -b 128 -`date +%Y%m%d%H%M`.mp3'	# record microphone input and output to date stamped mp3 file
alias mid='printf "\e[8;24;80;t"'							# resize participating terminals to classic 80x24 size
alias minicom='minicom -c on' 								# enable colour (sudo apt-get install minicom)
alias mkdirday='mkdir `date +%Y%m%d`_$1'						# (by Karl Voit) creates directory that starts with current day
alias mkdsp='sudo mknod /dev/dsp c 14 3 && sudo chmod 777 /dev/dsp'			# remake /dev/dsp
alias mkpkg='makepkg -csi'
alias mp3ogg='mp32ogg *.mp3 && rm *.mp3'
alias mpfb='mplayer -vo fbdev -xy 1024 -fs -zoom "$1"'					# watch a movie in linux without the X windows system
alias mpfb_='mplayer -vo fbdev2 -fs -zoom -xy 1440'
alias mtrue='sudo truecrypt /media/usbdisk/$USER.tc ~/$USER'
alias n2r='sudo /etc/init.d/nginx stop && sleep 2 && sudo /etc/init.d/nginx start'
alias ncftp='xtitle ncFTP ; ncftp'							# uses the function 'xtitle'
alias nytimes='lynx -term=vt100 http://nytimes.com'
alias passwords='passwd && rm -rf ~/.gnome2/keyrings/*'					# removes keyring passwords and lets you change user password
alias pipinstall='sudo pip install'
alias ppa-purge='sudo ppa-purge'
alias pstree='/sw/bin/pstree -g 2 -w'
alias puttyreload='export TERM=putty && source ~/.bashrc'
alias quota='quota -s'  								# human readable quota!
alias recursivetouch='find . -exec touch {} \;'						# be careful with this as it can modify time stamp of files
alias repo='gksudo gedit /etc/apt/sources.list'
alias restart-apache='sudo /etc/init.d/apache2 restart'
alias retheme='sudo gnome-settings-daemon'						# refreshes the theme to fix grey basic theme error at startup
alias rkhunter='sudo rkhunter -c'
alias rmao='find . -iname a.out -exec rm {} \;'
alias rm_DS_Store_files='find . -name .DS_Store -exec rm {} \;'				# removes all .DS_Store file from the current dir and below
alias rsync-me='sudo rsync -a -v --progress --delete --modify-window=1 -s $HOME /home/rsync'
alias scpresume='rsync --partial --progress --rsh=ssh'
# alias screencast='ffmpeg -f alsa -ac 2 -i hw:0,0 -f x11grab -r 30 -s 1280x800+0+0 -i :0.0 -acodec pcm_s16le -vcodec libx264 -vpre lossless_ultrafast -threads 0 -y output.mkv'
# alias screencast='ffmpeg -f x11grab -r 30 -s 1280x800 -i :0.0 $HOME/outputFile.mpg'	# record a screencast and convert it to an mpeg
alias screencast="ffmpeg -y -f alsa -ac 2 -i pulse -f x11grab -r 30 -s `xdpyinfo | grep 'dimensions:'|awk '{print $2}'` -i :0.0 -acodec pcm_s16le output.wav -an -vcodec libx264 -vpre lossless_ultrafast -threads 0 output.mp4"		# capture video of a linux desktop
alias screenr='screen -r $(screen -ls | egrep -o -e '[0-9]+' | head -n 1)'		# quick enter into a single screen session
alias screen_restart='sudo /etc/init.d/gdm restart'					# restarts screen to login screen so as to get back in
alias sdiff='/usr/bin/sdiff --expand-tabs --ignore-all-space --strip-trailing-cr --width=160'	# sdiff the way it was at IBM
alias sdirs='source ~/.dirs'
alias service='sudo service'								# access a system service
alias sh_diff='diff -abBpur'
alias sh_indent='indent -nsaf -npcs -cli2 -i2 -lp -nprs -nsaw -nut -cbi2 -bli0 -bls -nbad -npsl'
alias shot!='archey && scrot -d 5 -c screen_`date +%Y-%m-%d`.png'			# is also a function of shot which does the screen for one window
alias show_='cat ~/.dirs'
alias show-colors='~/.bin/colors.sh'
alias show-info='~/.bin/info.pl'
alias show_options='shopt'								# show_options: display bash options settings
alias showrepo='cat /etc/apt/sources.list `ls /etc/apt/sources.list.d/*.list` | egrep -v "^$"'
alias sh_svnstat="svn status | awk '/^[^?]/'"
alias sourcea='source ~/.aliases.bash'							# to source this file (to make changes active after editing)
alias spaceremover="sed -i 's/\s\+/ /g;s/\s*$//' $1"					# get rid of multiple spaces/tabs in a text file
alias ssinfo='perl ~/.scripts/ssinfo.pl'
# alias svnaddall='find "$PWD" -exec svn add {} 2>/dev/null \;'				# add all files recursively
alias svnaddall='svn status | grep "^\?" | awk "{print \$2}" | xargs svn add'
alias svndelall='svn status | grep "^\!" | awk "{print \$2}" | xargs svn delete'
alias svnrmallentries='find . -name .svn -print0 | xargs -0 rm -rf'			# remove all .svn directories recursively
alias tailm='multitail'
alias tarred='( ( D=`builtin pwd`; F=$(date +$HOME/`sed "s,[/ ],#,g" <<< ${D/${HOME}/}`#-%F.tgz); tar --ignore-failed-read --transform "s,^${D%/*},`date +${D%/*}.%F`,S" -czPf "$"F "$D" &>/dev/null ) & )'					# create date-based tgz of current dir (runs in background)
# alias themeinfo='perl ~/Scripts/info.pl'
alias thumbit='mogrify -resize 25%'
alias tinyurl='~/.scripts/tinyurl'							# converts url to tinyurl
alias tkeys='tmux list-keys'  								# shows all tmux keys
alias trace='~/.scripts/trace'								# visual traceroute
alias txt2md='rename 's/\.txt$/\.md$/i' *'						# batch rename extension of all .txt files to .md files in a folder
alias ugrub2='sudo update-grub2'							# update grub2
alias ugrub='sudo update-grub'								# update grub
alias updatedb='sudo updatedb'
alias updatefonts='sudo fc-cache -vf'
alias usbb='rsync -avz /media/usbdisk/ ~/backup/usb/'
alias utrue='sudo truecrypt -d'
alias viaco='task="$(basename "$(pwd)")"; if [ -f "$task.c" ]; then vi -c "set mouse=n" -c "set autoread" -c "vsplit $task.out" -c "split $task.in" -c "wincmd l" -c "wincmd H" $task.c; fi'							# setup Vim environment for USACO coding
alias video_record='mencoder -tv driver=v4l2:device=/dev/video1:input=1:norm=ntsc:alsa=1:adevice=hw.1:audiorate=48000:immediatemode=0:amode=1 tv:// -ovc lavc -lavcopts vcodec=mpeg4:vbitrate=1600:vhq:v4mv:keyint=250 -vf pp=de,pullup,softskip -oac mp3lame -lameopts abr:br=64:vol=2 -ffourcc xvid -o /home/me/Temp/$1.avi'	# record external video feed
alias webcam='mplayer -cache 128 -tv driver=v4l2:width=176:height=177 -vo xv tv:// -noborder -geometry "95%:93%" -ontop'	# mplayer webcam window for screencasts
alias webcam_record='ffmpeg -an -f video4linux2 -s 640x480 -r 15 -i /dev/video0 -vcodec mpeg4 -vtag XVID /home/soham/webcam_$1.avi'	# webcam record
alias webshare='python -c "import SimpleHTTPServer; SimpleHTTPServer.test();"'
alias wiki='wikipedia2text -p'								# convert wiki to text output
alias xinitrc='vim ~/.xinitrc'
alias xsnow='(killall xsnow ; sleep 3 ; exec xsnow -nosanta -notrees -norudolf -nokeepsnow >& /dev/null &)'	# xsnow


##################################################
# Network/Internet -oriented stuff		 #
##################################################

alias appson="netstat -lantp | grep -i stab | awk -F/ '{print $2}' | sort | uniq"	# view only the process name using an internet connection
alias bandwidth='dd if=/dev/zero of=/dev/null bs=1M count=32768'			# processor / memory bandwidthd? in GB/s
alias browse_bonjour='dns-sd -B'							# browse services advertised via Bonjour
# alias daemons='ls /var/run/daemons'  							# daemon managment (ommited for function)
alias dbdumpcp='scp -P 1234 username@12.34.56.78:$HOME/Backup/www/data/someSite/db.sql $HOME/Backup/data/db.sql'	# copy remote db to local
alias dns='cat /etc/resolv.conf'							# view DNS numbers
alias domain2ban='~/.scripts/Domain2Ban.sh'
alias estab='ss -p | grep STA' 								# view only established sockets (fails if "ss" is screensaver alias)
alias finchsync='java -jar ~/finchsync/finchsync.jar'					# start FinchSync Admin
# alias ftop='watch -d -n 2 'df; ls -FlAt;''						# like top, but for files
alias hdinfo='sudo hdparm -I /dev/sda'							# hard disk information - model/serial no.
alias hostip='wget http://checkip.dyndns.org/ -O - -o /dev/null | cut -d: -f 2 | cut -d\< -f 1'
alias hostname_lookup='lookupd -d'							# interactive debugging mode for lookupd (use tab-completion)
alias http_trace='pkt_trace port 80'							# to show all HTTP packets
alias iftop='sudo iftop -i enp0s3' 							# start "iftop" program (sudo apt-get install iftop)
alias ip4grep="grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}'"					# look for IPv4 address in files
alias ip='curl www.whatsmyip.org'
alias ip_info='ipconfig getpacket en1'							# info on DHCP server, router, DNS server, etc (for en0 or en1)
alias ipt80='sudo iptstate -D 80'							# check out only iptables state of http port 80 (requires iptstate)
alias ip_trace='pkt_trace ip'								# to show all IP packets
alias ipttrans='sudo iptstate -D 51413'							# iptables state of Transmission-Daemon port (requires iptstate)
alias listen='sudo netstat -pnutl' 							# lists all listening ports together with PID of associated process
alias lsock='sudo /usr/sbin/lsof -i -P'							# to display open sockets ( -P option to lsof disables port names)
alias memrel='free && sync && echo 3 > /proc/sys/vm/drop_caches && free'		# release memory used by the Linux kernel on caches
alias net1='watch --interval=2 "sudo netstat -apn -l -A inet"'
alias net2='watch --interval=2 "sudo netstat -anp --inet --inet6"'
alias net3='sudo lsof -i'
alias net4='watch --interval=2 "sudo netstat -p -e --inet --numeric-hosts"'
alias net5='watch --interval=2 "sudo netstat -tulpan"'
alias net6='sudo netstat -tulpan'
alias net7='watch --interval=2 "sudo netstat -utapen"'
alias net8='watch --interval=2 "sudo netstat -ano -l -A inet"'
alias netapps="lsof -P -i -n | cut -f 1 -d ' '| uniq | tail -n +2"
alias nethogs='sudo nethogs wlp2s0' 							# start "nethogs" program (sudo apt-get install nethogs)
alias netl='sudo nmap -sT -O localhost'
alias netscan='sudo iwlist wlp2s0 scan'							# to scan your environment for available networks, do the following
alias netstats='sudo iwspy wlp2s0'							# if card supports it, you can collect wireless statistics by using
alias network='sudo lshw -C network' 							# view network device info
alias networkdump='sudo tcpdump not port 22' 						# dump all the network activity except ssh stuff
alias nmr='sudo /etc/rc.d/networkmanager restart'
alias nsl='netstat -f inet | grep -v CLOSE_WAIT | cut -c-6,21-94 | tail +2'		# show all programs connected or listening on a network port
alias ns='netstat -alnp --protocol=inet | grep -v CLOSE_WAIT | cut -c-6,21-94 | tail +2'
alias openports='sudo netstat -nape --inet' 						# view open ports
alias oports="echo 'User:      Command:   Port:'; echo '----------------------------' ; lsof -i 4 -P -n | grep -i 'listen' | awk '{print \$3, \$1, \$9}' | sed 's/ [a-z0-9\.\*]*:/ /' | sort -k 3 -n |xargs printf '%-10s %-10s %-10s\n' | uniq"	# lsof (cleaned up for just open listening ports)
alias pkt_trace='sudo tcpflow -i wlp2s0 -c'
alias ports='lsof -i -n -P' 								# view programs using an internet connection
alias portstats='sudo netstat -s' 							# show statistics for all ports
alias proxy1='ssh -p 1234 -D 5678 username@12.34.56.78'					# SOCKS proxy - these anonomise browsing - 12.34.56.78
alias proxy2='ssh -p 8765 -D 4321 username@87.65.43.21'					# SOCKS proxy - these anonomise browsing - 87.65.43.21
alias QUERY='psql -h $MYDBHOST -p 5432 -d $MYDB -U $MYLOGIN --no-align'			# lazy SQL QUERYING
alias randomip='echo $((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256))'	# generate a random IP address
alias ramvalue='sudo dd if=/dev/mem | cat | strings'					# will show you all the string (plain text) values in ram
alias randommac='python -c "from itertools import imap; from random import randint; print ':'.join(['%02x'%x for x in imap(lambda x:randint(0,255), range(6))])"'										# generate random valid mac addresses
alias rdp='rdesktop -u "$USER" -g 1600x1200 -D -r disk:home=/home -r clipboard:PRIMARYCLIPBOARD'	# quick full screen RDP connection
alias remote='ssh -p 1234 12.34.56.78'							# access some remote host
alias restartnet='sudo /etc/rc.d/network restart;sudo /etc/rc.d/wicd restart'
alias rssup='php /srv/http/rssupdate.php'
alias setessid='sudo iwconfig wlp2s0 essid network-essid'				# set the essid, which identifies the network access point you want
alias smtp_trace='pkt_trace port smtp'							# to show all SMTP packets
alias someDBdump='sudo mysqldump someDB -usoham -p > $HOME/www/_dbs/someDB.sql'
alias spavr='gtkterm -c avr'
# alias spavr='sudo chmod a=rw /dev/ttyUSB0; gtkterm -c avr'
alias speedtest='speedtest --share | grep "Download\|Upload\|Share"'							# speedtest - test internet speed and share image of results
alias spk800i='gtkterm -c k800i'
# alias spk800i='sudo chmod a=rw /dev/rfcomm0; gtkterm -c k800i'
alias sql='mysql -p -u soham'
alias sync='java -jar ~/finchsync/finchsync.jar -nogui'					# sync to PDA .. well, that'll be a sync then! - start FinchSync SVR
alias syncoff='java -jar ~/Apps/FinchSync/finchsync.jar -stopserver'			# sync to PDA .. well, that'll be a sync then! - stop FinchSync SVR
alias tcpstats='sudo netstat -st' 							# show statistics for tcp ports
alias tcp_='sudo netstat -atp' 								# list all TCP ports
alias tcp_trace='pkt_trace tcp'								# to show all TCP packets
alias topsites='curl -s -O http://s3.amazonaws.com/alexa-static/top-1m.csv.zip ; unzip -q -o top-1m.csv.zip top-1m.csv ; head -1000 top-1m.csv | cut -d, -f2 | cut -d/ -f1 > topsites.txt'							# get a list of top 1000 sites from alexa
alias tproxy='ssh -ND 8118 user@server&; export LD_PRELOAD="/usr/lib/libtsocks.so"'	# creates a proxy based on tsocks
alias udpstats='sudo netstat -su' 							# show statistics for udp ports
alias udp='sudo netstat -aup' 								# list all UDP ports
alias udp_trace='pkt_trace udp'								# to show all UDP packets
alias uploads='cd /some/folder'								# access some folder
alias vncup='x11vnc -nopw -ncache 10 -display :0 -localhost'
alias website_dl='wget --random-wait -r -p -e robots=off -U mozilla "$1"'		# download an entire website
alias website_images='wget -r -l1 --no-parent -nH -nd -P/tmp -A".gif,.jpg" "$1"'	# download all images from a site
alias whois='whois -H'
alias wireless_sniffer='sudo ettercap -T -w out.pcap -i wlp2s0 -M ARP / //'		# sniff who are using wireless. Use wireshark to watch out.pcap
alias wscan_='iwlist scan'								# terminal network scan for wireless signals
alias wwwmirror2='wget -k -r -l ${2} ${1}'						# wwwmirror2 usage: wwwmirror2 [level] [site_url]
alias wwwmirror='wget -ErkK -np ${1}'



##################################################
# Package holding, making, and installation	 #
##################################################

alias checkinstall-force='sudo checkinstall --dpkgflags "--force-overwrite"'
alias checkinstall-noinstall='sudo checkinstall -y --fstrans=no --install=no'
#alias checkinstall='sudo checkinstall -y --fstrans=no'
alias debinstall-force='sudo dpkg -i --force-overwrite'
alias debinstall='sudo dpkg -i'
alias diffinstall='diff /tmp/install.pre /tmp/install.pos | grep \"^>\" | sed \"s/^> //g\"'	# run diffinstall fourth, after diffinstall to show what files were copied in your system
alias postinstall='sudo find / ! \( -path /proc -prune -o -path /tmp -prune -o -path /dev -prune -o -path /mnt -prune \) > /tmp/install.pos'	# run postinstall third, after "make install"
alias preinstall='sudo find / ! \( -path /proc -prune -o -path /tmp -prune -o -path /dev -prune -o -path /mnt -prune \) > /tmp/install.pre'	# run preinstall first, then "make install"



##################################################
# Permissions					 #
##################################################

alias 000='chmod 000 -R'
alias 640='chmod 640 -R'
alias 644='chmod 644 -R'									# default permission for ('~/.dmrc' file)
alias 755='chmod 755 -R'									# default permissions for $HOME (excluding '~/.dmrc' file)
alias 775='chmod 775 -R'
alias 777='chmod 777 -R'
alias mx='chmod a+x'
alias perm='stat --printf "%a %n \n "'								# requires a file name e.g. perm file
alias permall='777'
alias permhome='chmod 755 -R $HOME && chmod 644 $HOME/.dmrc'
alias restoremod='chgrp users -R .;chmod u=rwX,g=rX,o=rX -R .;chown $(pwd |cut -d / -f 3) -R .'	# restore user,group and mod of an entire website



##################################################
# Personal help					 #
##################################################

alias a?='cat ~/.alias.help'
alias dn='OPTIONS=$(\ls -F | grep /$); select s in $OPTIONS; do cd $PWD/$s; break;done'
alias espanol='echo -e \"á Á é É í Í ó Ó ú Ú ñ Ñ ü Ü ¿ ¡ ¢ ‘ ’ “ ” „ ‚ …\"'
alias f?='cat ~/.function.help'
alias help='OPTIONS=$(\ls ~/.tips -F);select s in $OPTIONS; do less ~/.tips/$s; break;done'
alias testh='help test|sed -e :a -e "$!N;s/\(-n STRING\)\n/\1, /;s/\n\( \{23\}\| \{4\}\([a-z]\)\)/ \2/;ta;P;D"|sed "s/ \{1,\}/ /g;/^ $/d;/:$/s/^/\n/"|sed -n "/File operators:/,\$p"'						# test quick help alias



##################################################
# Relinux stuff				 	 #
##################################################

alias relinux-clean='sudo relinux clean $HOME/.relinux.conf'		# cleans up files made by relinux
# alias relinux-clean='sudo relinux clean $HOME/relinux.conf'		# cleans up files made by relinux
alias relinux-config='sudo relinux config'				# generates a configuration file in the current directory
# alias relinux-fullclean='sudo relinux fullclean $HOME/relinux.conf'	# cleans up files made by relinux, including the ISO file
alias relinux-fullclean='sudo relinux fullclean $HOME/.relinux.conf'	# cleans up files made by relinux, including the ISO file
# alias relinux-iso='sudo relinux iso $HOME/relinux.conf'		# runs both 'relinux-onlyiso' & 'relinux-squashfs'
alias relinux-iso='sudo relinux iso $HOME/.relinux.conf'		# runs both 'relinux-onlyiso' & 'relinux-squashfs'
# alias relinux-onlyiso='sudo relinux onlyiso $HOME/relinux.conf'	# generates .iso file based on .squashfs file from 'relinux-squashfs'
alias relinux-onlyiso='sudo relinux onlyiso $HOME/.relinux.conf'	# generates .iso file based on .squashfs file from 'relinux-squashfs'
# alias relinux-squashfs='sudo relinux squashfs $HOME/relinux.conf'	# generates a .squashfs file from your system
alias relinux-squashfs='sudo relinux squashfs $HOME/.relinux.conf'	# generates a .squashfs file from your system



##################################################
# Remastersys stuff				 #
##################################################

alias remastersys-backup-custom='sudo remastersys backup custom.iso'	# to make a livecd/dvd backup and call the iso custom.iso
alias remastersys-backup='sudo remastersys backup'			# to make a livecd/dvd backup of your system
alias remastersys-clean='sudo remastersys clean'			# to clean up temporary files of remastersys
alias remastersys-dist-cdfs='sudo remastersys dist cdfs'		# to make a distributable livecd/dvd filesystem only
alias remastersys-dist-custom='sudo remastersys dist iso custom.iso'	# to make a distributable iso named custom.iso but only if cdfs is present
alias remastersys-dist='sudo remastersys dist'				# to make a distributable livecd/dvd of your system



##################################################
# Secure-delete substitution			 #
##################################################

alias sfill-freespace='sudo sfill -I -l -l -v'
alias sfill-f='sudo sfill -f -l -l -v -z'
alias sfill='sudo sfill -l -l -v -z'
alias sfill-usedspace='sudo sfill -i -l -l -v'
alias smem-f='sudo sdmem -f -l -l -v'
alias smem-secure='sudo sdmem -v'
alias smem='sudo sdmem -l -l -v'
alias srm-m='sudo srm -f -m -z -v'
alias srm='sudo srm -f -s -z -v'
alias sswap-sda5='sudo sswap -f -l -l -v -z /dev/sda5'
alias sswap='sudo sswap -f -l -l -v -z'
alias swapoff='sudo swapoff /dev/sda5'
alias swapon='sudo swapon /dev/sda5'



##################################################
# Set up auto extension stuff			 #
##################################################

###### If -s flags present, define suffix alias: if command word on command line is in form `text.name',
# where text is any non-empty string, its replaced by text 'value text.name'. Note that names treated as literal
# string, not pattern.  A trailing space in value is not special in this case. For example, alias -s ps=gv
# will cause command `*.ps' to be expanded to `gv *.ps'. As alias expansion is carried out earlier than globbing,
# `*.ps' will then be expanded. Suffix aliases constitute different name space from other aliases (so in above
# example its still possible to create alias for command ps) and two sets are never listed together.
# alias -s avi=mplayer
# alias -s bz2=tar -xjvf
# alias -s com=$BROWSER
# alias -s cpp=vim
# alias -s doc=soffice
# alias -s eps=eog
# alias -s gif=eog
# alias -s gz=tar -xzvf
# alias -s html=$BROWSER
# alias -s img=mplayer
# alias -s install=$EDITOR
# alias -s iso=mplayer
# alias -s java=$EDITOR
# alias -s jpg=eog
# alias -s mkv=mplayer
# alias -s mp3=mplayer
# alias -s mpeg=mplayer
# alias -s mpg=mplayer
# alias -s mws=maple
# alias -s net=$BROWSER
# alias -s odt=soffice
# alias -s org=$BROWSER
# alias -s pdf=evince
# alias -s php=$BROWSER
# alias -s PKGBUILD=vim
# alias -s png=eog
# alias -s ppt=soffice
# alias -s ps=gv
# alias -s se=$BROWSER
# alias -s sh=vim
# alias -s sxw=soffice
# alias -s tex=$EDITOR
# alias -s txt=$EDITOR
# alias -s wmv=mplayer
# alias -s xls=soffice



##################################################
# Shred substitution				 #
##################################################

alias shred-sda-r='sudo shred -v -z -n 1 /dev/sda'
alias shred-sda='sudo shred -v -z -n 0 /dev/sda'
alias shred-sdb-r='sudo shred -v -z -n 1 /dev/sdb'
alias shred-sdb='sudo shred -v -z -n 0 /dev/sdb'
alias shred-sdc-r='sudo shred -v -z -n 1 /dev/sdc'
alias shred-sdc='sudo shred -v -z -n 0 /dev/sdc'
alias shred-sdd-r='sudo shred -v -z -n 1 /dev/sdd'
alias shred-sdd='sudo shred -v -z -n 0 /dev/sdd'
alias shred-sde-r='sudo shred -v -z -n 1 /dev/sde'
alias shred-sde='sudo shred -v -z -n 0 /dev/sde'
alias shred-sdf-r='sudo shred -v -z -n 1 /dev/sdf'
alias shred-sdf='sudo shred -v -z -n 0 /dev/sdf'
alias shred-sdg-r='sudo shred -v -z -n 1 /dev/sdg'
alias shred-sdg='sudo shred -v -z -n 0 /dev/sdg'



##################################################
# Xterm and Aterm				 #
##################################################

alias aterm='xterm -ls -fg gray -bg black'
alias termb='xterm -bg AntiqueWhite -fg NavyBlue &'
alias termg='xterm -bg AntiqueWhite -fg OliveDrab &'
alias termr='xterm -bg AntiqueWhite -fg DarkRed &'
alias term='xterm -bg AntiqueWhite -fg Black &'
alias xsu='xterm -fn 7x14 -bg DarkOrange4 -fg white -e su &'
alias xtop='xterm -fn 6x13 -bg LightSlateGray -fg black -e top &'

##################################################
# Brightness Substitution				 #
##################################################

alias bright='echo "12345" | sudo sh -c "echo 7500 >/sys/class/backlight/intel_backlight/brightness"'
alias dim='echo "12345" | sudo sh -c "echo 800 >/sys/class/backlight/intel_backlight/brightness"'


##################################################
##################################################
##################################################




alias source='.'

if [ -f /etc/bash.command-not-found ]; then
    . /etc/bash.command-not-found
fi







