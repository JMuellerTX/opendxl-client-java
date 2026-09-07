Client Configuration Update via Command Line
============================================

The ``updateconfig`` command line operation can be used to update a previously
provisioned client with the latest information from a management server
(ePO or OpenDXL Broker).

    .. note::
    
        ePO-managed environments must have 4.0 (or newer) versions of DXL ePO extensions installed.

The ``updateconfig`` operation performs the following:

* Retrieves the latest CA certificate bundle from the server and stores it
  at the file referenced by the ``BrokerCertChain`` setting in the ``[Certs]``
  section of the ``dxlclient.config`` file.

* Retrieves the latest broker information and updates the ``[Brokers]`` and
  ``[BrokersWebSockets]`` sections of the ``dxlclient.config`` file with that information.

Basic Example
*************

For example:

    .. parsed-literal::

        java -jar dxlclient-\ |version|\-all.jar updateconfig config myserver

    .. note::

        Ensure that the ``-all`` version of the dxlclient ``.jar`` file is specified.

For this example, ``config`` is the name of the directory in which the
``dxlclient.config`` file resides and ``myserver`` is the hostname or
IP address of ePO or an OpenDXL Broker.

When prompted, provide credentials for the OpenDXL Broker Management Console
or ePO (the ePO user must be an administrator)::

    Enter server username:
    Enter server password:

If the operation is successful, output similar to the following
should be displayed::

    INFO: Updating certs in config/ca-bundle.crt
    INFO: Updating DXL config file at config/dxlclient.config

To avoid the username and password prompts, supply the appropriate
command line options (``-u`` and ``-p``):

    .. parsed-literal::

        java -jar dxlclient-\ |version|\-all.jar updateconfig config myserver -u myuser -p mypass

    .. note::

        Ensure that the ``-all`` version of the dxlclient ``.jar`` file is specified.

Additional Options
******************

The update operation assumes that the default web server port is 8443,
the default port under which the ePO web interface and OpenDXL Broker Management
Console is hosted.

A custom port can be specified via the ``-t`` option.

For example:

    .. parsed-literal::

        java -jar dxlclient-\ |version|\-all.jar updateconfig config myserver -t 443

    .. note::

        Ensure that the ``-all`` version of the dxlclient ``.jar`` file is specified.


The management server's certificate is validated during TLS session
negotiation. By default it is validated against the JVM's trusted CAs.
Management servers commonly use a certificate issued by a private CA -- an
ePO server, for example, issues its web certificate from its own server CA --
which the JVM does not trust. Export that CA as a PEM file (one or more
certificates concatenated) and supply it with the ``-e`` option:

    .. parsed-literal::

        java -jar dxlclient-\ |version|\-all.jar updateconfig config myserver -e epo-ca.pem

The host name given on the command line must match the certificate; an IP
address usually does not. Validation can be disabled with ``--insecure``, which
is not recommended because it leaves the transport of the credentials and of the
returned certificates unprotected against interception.

    .. note::

        Ensure that the ``-all`` version of the dxlclient ``.jar`` file is specified.

Routing client configuration update operation through a proxy
*************************************************************

If the remote call to a provisioning server (ePO or OpenDXL Broker) used during a client configuration update must be
routed through a proxy, then use standard Java system properties to declare the https proxy host, port, user name,
and password. (`<https://docs.oracle.com/javase/8/docs/technotes/guides/net/proxies.html>`_)

For example:

    .. parsed-literal::

        java -Dhttps.proxyHost=proxy.mycompany.com -Dhttps.proxyPort=3128 -Dhttps.proxyUser=proxyUser -Dhttps.proxyPassword=proxyPassword -jar dxlclient-\ |version|\-all.jar updateconfig config myserver

