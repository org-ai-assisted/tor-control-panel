#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## The PyQt help dialogs, kept separate from info.py so the config-logic layer
## (torrc_gen / tor_status / validators / privilege / ...) can import info.py
## for its text strings without pulling in PyQt -- a CLI can use the config code
## with no GUI dependency.

from PyQt5 import QtWidgets

from .info import tcp_custom_bridges_help

def show_help_censorship():
    reply = QtWidgets.QMessageBox(QtWidgets.QMessageBox.NoIcon, 'Censorship Circumvention Help',
                                  '''<p><b>  Censorship Circumvention Help</b></p>

<p>If you are unable to connect to the Tor network, it could be that your Internet Service
Provider (ISP) or another agency is blocking Tor. Often, you can work around this problem
by using Tor Bridges, which are unlisted relays that are more difficult to block.</p>

<p>Tor bridges are the recommended way to circumvent Tor censorship. You should always take them as your first
option to help bypass censorship. However, if you are living in a heavily censored area where all the Tor bridges
are blocked, you may need to use third-party censorship circumvention tools instead. In such a case, you should
choose not to use Tor bridges.</p>

<p>Using a third-party censorship circumvention tool may harm your security and/or anonymity. However,
if you do need it, the following is an instruction on how to connect to the Tor network using different
censorship circumvention tools:</p>

<blockquote><b>1. VPN</b><br>
1. Establish a connection to the VPN server; 2. Click the "Back" button on this page to return to the first page;
3. Click the "Connect" button on the first page.</blockquote>

<blockquote><b>2. HTTP/Socks Proxy</b><br>
1. Choose not to use Tor bridges on this page; 2. Click the "Next" button to proceed to the Proxy Configuration page;
3. Configure a proxy.</blockquote>

<blockquote><b>3. Specialized Tool</b><br>
1. Identify the tool's listening port, including protocol and port number; 2. Choose not to use Tor bridges on
this page; 3. Click the "Next" button to proceed to the Proxy Configuration page; 4. Configure a proxy.</blockquote>
''', QtWidgets.QMessageBox.Ok)
    reply.exec_()


def show_proxy_help():
    reply = QtWidgets.QMessageBox(QtWidgets.QMessageBox.NoIcon, 'Proxy Configuration Help',
                                  '''<p><b>  Proxy Help</b></p>
                                  <p>In some situations, you may want to route your traffic through a proxy server
                                  before connecting to the Tor network. For example, if you are using a third-party
                                  censorship circumvention tool to bypass Tor censorship, you need to configure Tor
                                  to connect to the tool's listening port.</p>

<p>The following is a brief explanation of what each field means and how to find the correct value:</p>

<blockquote><b>1. Proxy Type</b><br>
The proxy type is the protocol you use to communicate with the proxy server. Since there are only three options,
 you can try each to see which one works.</blockquote>

<blockquote><b>2. Proxy IP/hostname</b><br>
You need to know the address you are trying to connect to. If connecting to a local proxy, use 127.0.0.1,
which refers to localhost.</blockquote>

<blockquote><b>3. Proxy Port Number</b><br>
You need to know the port number you are trying to connect to. It should be a positive integer between 1 and 65535.
 For well-known tools, you can look up the port number online.</blockquote>

<blockquote><b>4. Username and Password</b><br>
If you do not know these, leave them blank and see if the connection succeeds. In most cases, they are not required.
</blockquote>''', QtWidgets.QMessageBox.Ok)
    reply.exec_()


def custom_bridges_help():
    reply = QtWidgets.QMessageBox(QtWidgets.QMessageBox.NoIcon, 'Custom Bridges Help',
                         tcp_custom_bridges_help(), QtWidgets.QMessageBox.Ok)
    reply.exec_()
