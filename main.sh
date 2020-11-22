  mkdir ~/ricingStuff
  cd ~/ricingStuff

# Remove gnome
  sudo apt-get remove gnome* -y
  sudo apt-get purge gnome* -y 

# Install i3
  sudo apt-get install i3 -y

# Install powerline fonts
  sudo apt-get install fonts-powerline

# Install i3 gaps
  sudo apt install libxcb1-dev libxcb-keysyms1-dev  libxcb-util0-dev libxcb-icccm4-dev libyajl-dev libstartup-notification0-dev libxcb-randr0-dev libev-dev libxcb-cursor-dev libxcb-xinerama0-dev libxcb-xkb-dev libxkbcommon-dev libxkbcommon-x11-dev autoconf xutils-dev libtool automake
  git clone https://www.github.com/Airblader/i3 i3-gaps
  cd i3-gaps
  git checkout gaps && git pull
  autoreconf --force --install
  rm -rf build
  mkdir build
  cd build
  ../configure --prefix=/usr --sysconfdir=/etc --disable-sanitizers
  make
  sudo make install
