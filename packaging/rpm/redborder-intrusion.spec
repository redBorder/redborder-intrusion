%undefine __brp_mangle_shebangs

Name: redborder-intrusion
Version: %{__version}
Release: %{__release}%{?dist}
BuildArch: noarch
Summary: Main package for redborder intrusion

License: AGPL 3.0
URL: https://github.com/redBorder/redborder-intrusion
Source0: %{name}-%{version}.tar.gz

Requires: bash dialog dmidecode rsync nc telnet redborder-common redborder-chef-client redborder-rubyrvm redborder-cli rb-register bridge-utils bpctl net-tools bind-utils ipmitool watchdog bp_watchdog snort3 dhclient
Requires: chef-workstation
Requires: network-scripts network-scripts-teamd
Requires: redborder-cgroups

%description
%{summary}

%prep
%setup -qn %{name}-%{version}

%build

%install
mkdir -p %{buildroot}/etc/redborder
mkdir -p %{buildroot}/usr/lib/redborder/bin
mkdir -p %{buildroot}/usr/lib/redborder/scripts
mkdir -p %{buildroot}/usr/lib/redborder/lib
mkdir -p %{buildroot}/etc/profile.d
mkdir -p %{buildroot}/var/chef/cookbooks
mkdir -p %{buildroot}/etc/chef/
install -D -m 0644 resources/redborder-intrusion.sh %{buildroot}/etc/profile.d
install -D -m 0644 resources/dialogrc %{buildroot}/etc/redborder
cp resources/bin/* %{buildroot}/usr/lib/redborder/bin
cp resources/scripts/* %{buildroot}/usr/lib/redborder/scripts
cp -r resources/etc/chef %{buildroot}/etc/
cp resources/etc/rb_sysconf.conf.default %{buildroot}/etc/
chmod 0755 %{buildroot}/usr/lib/redborder/bin/*
chmod 0755 %{buildroot}/usr/lib/redborder/scripts/*
install -D -m 0644 resources/lib/rb_wiz_lib.rb %{buildroot}/usr/lib/redborder/lib
install -D -m 0644 resources/lib/wiz_conf.rb %{buildroot}/usr/lib/redborder/lib
install -D -m 0644 resources/lib/wizard_helper.rb %{buildroot}/usr/lib/redborder/lib
install -D -m 0644 resources/lib/rb_config_utils.rb %{buildroot}/usr/lib/redborder/lib
install -D -m 0644 resources/lib/rb_functions.sh %{buildroot}/usr/lib/redborder/lib
install -D -m 0644 resources/systemd/rb-init-conf.service %{buildroot}/usr/lib/systemd/system/rb-init-conf.service
install -D -m 0755 resources/lib/dhclient-enter-hooks %{buildroot}/usr/lib/redborder/lib/dhclient-enter-hooks

%pre

%post
[ -f /usr/lib/redborder/bin/rb_rubywrapper.sh ] && /usr/lib/redborder/bin/rb_rubywrapper.sh -c
systemctl daemon-reload
# adjust kernel printk settings for the console
echo "kernel.printk = 1 4 1 7" > /usr/lib/sysctl.d/99-redborder-printk.conf
/sbin/sysctl --system > /dev/null 2>&1

%files
%defattr(0755,root,root)
/usr/lib/redborder/bin
/usr/lib/redborder/scripts
%defattr(0755,root,root)
/etc/profile.d/redborder-intrusion.sh
/usr/lib/redborder/lib/dhclient-enter-hooks
%defattr(0644,root,root)
/etc/chef/
/etc/rb_sysconf.conf.default
/etc/redborder
/usr/lib/redborder/lib/rb_wiz_lib.rb
/usr/lib/redborder/lib/wiz_conf.rb
/usr/lib/redborder/lib/wizard_helper.rb
/usr/lib/redborder/lib/rb_config_utils.rb
/usr/lib/redborder/lib/rb_functions.sh
/usr/lib/systemd/system/rb-init-conf.service
%doc

%changelog

* Mon Mar 21 2021 Miguel Negron <manegron@redborder.com> - 0.0.1-1
- first spec version
