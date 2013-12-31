# makefile
# Created by IBM WorkFrame/2 MakeMake at 2:49:51 on 24 Oct 2003
#
# The actions included in this make file are:
#  Compile::C++ Compiler
#  Link::Linker

.SUFFIXES:

.SUFFIXES: \
    .cpp .obj 

.cpp.obj:
    @echo " Compile::C++ Compiler "
    icc.exe /O /G5 /C %s

{G:\EVGEN\INET\SpamKill}.cpp.obj:
    @echo " Compile::C++ Compiler "
    icc.exe /O /G5 /C %s

all: \
    .\SpamKill.exe

.\SpamKill.exe: \
    .\Sk_config.obj \
    .\SpamKill.obj \
    .\Sk_blackList.obj \
    {$(LIB)}tcpip32.lib
    @echo " Link::Linker "
    icc.exe @<<
     /B" /exepack:2 /packd /optfunc"
     /FeSpamKill.exe 
     tcpip32.lib 
     .\Sk_config.obj
     .\SpamKill.obj
     .\Sk_blackList.obj
<<

.\Sk_config.obj: \
    G:\EVGEN\INET\SpamKill\Sk_config.cpp \
    {G:\EVGEN\INET\SpamKill;$(INCLUDE);}SK_config.hpp

.\Sk_blackList.obj: \
    G:\EVGEN\INET\SpamKill\Sk_blackList.cpp

.\SpamKill.obj: \
    G:\EVGEN\INET\SpamKill\SpamKill.cpp \
    {G:\EVGEN\INET\SpamKill;$(INCLUDE);}SK_config.hpp \
    {G:\EVGEN\INET\SpamKill;$(INCLUDE);}Sk_mail.hpp \
    {G:\EVGEN\INET\SpamKill;$(INCLUDE);}Sk_history.hpp
