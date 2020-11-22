  mkdir -p ~/ricingStuff
  cd ~/ricingStuff

# Remove gnome
  #sudo apt-get remove gnome* -y
  #sudo apt-get purge gnome* -y 

# Setup source list
  sudo mv sources.list /etc/apt/sources.list
  sudo apt-get update
  sudo apt-get upgrade -y
  sudo apt-get dist-upgrade -y

# Install i3
  sudo apt-get install i3 -y

# Install powerline fonts
  sudo apt-get install fonts-powerline

# Install i3 gaps
  ## TODO

# Resolve xbacklight issue
  Identifier='Identifier "${xrandr --verbose | grep Identifier | head -1 | awk '{ print $2 }'}"'
  Driver='Driver "intel"'
  Option='Option "Backlight" "${ls /sys/class/backlight}"'
  read -r -d '' FILE_CONTENT << EOM
Section "Device"
    $Identifier
    $Driver
    $Option
EndSection
EOM
  mkdir /etc/X11/xorg.conf.d/
  echo $FILE_CONTENT > x.conf


# Install polybar
  sudo apt -t buster-backports install polybar
  sudo apt-get install mpd -y
  mkdir -p ~/.config/polybar/
  cp /usr/share/doc/polybar/config ~/.config/polybar/

  polybar example &> /dev/null 

