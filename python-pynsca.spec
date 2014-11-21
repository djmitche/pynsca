%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
%{!?pyver: %define pyver %(%{__python} -c "import sys ; print sys.version[:3]")}

%global real_name pynsca

Name: python-pynsca
Version: 1.6a
Release: 1%{?dist}
License: MPLv3
Source0: https://pypi.python.org/packages/source/p/%{real_name}/%{real_name}-%{version}.tar.gz
Group: Development/Libraries
BuildArch: noarch
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
BuildRequires: python-devel
BuildRequires: python-setuptools

Summary: Simple Python interface to Nagios Service Check Architecture
URL: https://github.com/djmitche/pynsca

%description
A very simple module to allow nagios service check results to be submitted via
NSCA.

%prep
%setup -n %{real_name}-%{version}

%build
%{__python} setup.py build

%install
rm -rf %{buildroot}
%{__python} setup.py install -O1 --skip-build --root %{buildroot}

%clean
rm -rf %{buildroot}

%post

%files
%defattr(-,root,root,-)
%doc README.rst
%attr(0755,root,root) %{python_sitelib}/%{real_name}.py*
%{python_sitelib}/%{real_name}-%{version}-py%{pyver}.egg-info/

%dir

%changelog

* Thu Feb 20 2014 Xavier Devlamynck <xd@eyepea.eu> - 1.5-1
- Initial release
