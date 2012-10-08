package DCY::Utils;

use 5.008005;
use strict;
use warnings;
use vars qw( @ISA @EXPORT $VERSION @_Error );

require Exporter;
use Carp;

my $VERMAJOR     = "1";
my ( $VERMINOR ) = ( '$Revision: 9 $' =~ /(\d+)/ );

$VERSION      = "$VERMAJOR.$VERMINOR";
@ISA          = qw( Exporter );
@EXPORT       = qw( istty send_mail pgp_decrypt pgp_encrypt );

=pod

=head1 NAME

DCY::Utils - Perl module for Easy PGP/SFTP Scripting.

=head1 SYNOPSIS

use DCY::Utils;

=head1 SUB MODULES

DCY::Utils::FTP       - FTP Tools

DCY::Utils::PGP       - PGP (GnuPG) Tools

DCY::Utils::Bookmarks - NcFTP bookmark Tools

=head1 DESCRIPTION

This toolkit Provides utilities for the various perl scripts which
send and/or retrieve information between ftp and internal servers.

At it's core it's primarily a wrapper for the Net::FTP and Net::SCP CPAN modules
for easier use in perl scripts.

Functions return a true value on sucess and undef upon errer.
Use the $pkg->error() method to retrieve any error messages.

=head1 STRUCTURES

=over

=item FTP Hash

The FTP hash is the primary hash used to pass options to the FTP Contstructor.

It's a hash constructed of the following key=>value pairs:

        HOST     => The HOST or IP address to connect to
        USER     => The Username to log in as
        PASS     => The Password to use
        PASV     => 0 == off, 1 == on
        PORT     => The FTP port to use (default is 21)
        RDIR     => The remote directory to CD to once connected
        LDIR     => The local directory to CD to once connected
        SFTP     => Set to 1 if you wish to use SFTP instead of FTP
        IDENTITY => The identity file to use with SFTP (defaults to $HOME/.ssh/identity)
        RENAME   => If defined, any source files that are
                    sucessfully retrieved or sent are renamed to
                    include this as a suffix.  (used to rename files
                    after a transfer so we don't get them again on
                    the next run)

=item @files list

This is just a normal array which contains a list of files you want to work
with.  The list may include paths relative to RDIR, absolute paths, and/or
any valid ftp file patterns.

=back

=head1 BASE FUNCTIONS

=over

=item istty()

Returns true if the script is currently running from a prompt (interactive)
or false if otherwise (e.g. from cron).

=cut

## Functions

sub istty { return -t STDIN && -t STDOUT; }     # Check for interactive terminal

=item send_mail( $TO, $SUBJECT, @MESSAGE );

Sends an email message using /bin/mail.

=cut

sub send_mail {
    my ( $mail_to, $mail_subject, @mail_message ) = @_;
    my $mail_bin = q(/bin/mail);

    if ( not -x $mail_bin ) {
        carp "$mail_bin does not exist on this system, cannot send mail";
        return;
    }

    return if not defined $mail_to;
    return if not defined $mail_subject;
    return if not @mail_message;

    open MAIL, "|$mail_bin -s \"$mail_subject\" $mail_to"
        or croak "Error executing $mail_bin";
    print MAIL map { "$_\n" } @mail_message;
    close MAIL;

    return 1;
}

=item Error Queue

=item $pkg->error

Returns and clears the last error in scalar context.
Returns and then clears all errors when called in list context.

=item $pkg->error_clear

clears the queue and returns the number of messages cleared.

=item $pkg->error_count

Returns the number of messages in the queue.

=back

=cut

# Error Queue Accessors
@_Error = ();                                       # The error queue array
sub oops  { shift->error(@_); return undef; }       # Internal error accessor method
sub error_count { return scalar @_Error; };         # Returns a count of errors in the queue
sub error_clear { my @error = shift->error; return scalar @error; };
sub error {                                         # Either Returns or pushes a message into the error queue
    shift;                                          # The queue is cleared in list context.

    if ( @_ ) { return push @_Error, @_; }

    return unless defined wantarray;

    if ( wantarray ) {          # If we're called in list context
        my @error = @_Error;    # Copy the error array
        @_Error = ();           # Clear the global error array
        return ( @error );      # Return the previous contents
    }

    return pop @_Error;         # Return the last error
}

package DCY::Utils::PGP;
our @ISA = qw( DCY::Utils );

=head1 PGP FUNCTIONS

=over

=item Constructor

$pgp = DCY::Utils::PGP->new( FileName );

=cut

sub new {
    my $pkg = shift;
    return bless {
       '_FILE' => shift,
       '_KEY'  => '',
       '_PASS' => '',
       '_BIN'  => '/usr/bin/gpg',
       '_OVERWITE' => 0,
       '_OPTIONS' => [
                        '--batch',
                        '--no-tty',
                        '--quiet',
                        '--always-trust',
                        '--skip-verify',
                        '--yes'
                     ],
    }, $pkg;
}

=item Methods

=over

=item $pkg->file : Set or return the file.

=item $pkg->bin  : Set or return the PGP binary (defaults to '/usr/bin/gpg')

=item $pkg->key  : Set or return the PGP key (for encrypt).

=item $pkg->password : Set or return the PGP Password (for decrypt).

=item $pkg->options : Set or return the PGP Command Options (don't use unless you're sure you know what you're doing)

=back

=cut

sub key      { my $pkg = shift; @_ ? $pkg->{'_KEY'}  = shift : $pkg->{'_KEY'};  }
sub bin      { my $pkg = shift; @_ ? $pkg->{'_BIN'}  = shift : $pkg->{'_BIN'};  }
sub file     { my $pkg = shift; @_ ? $pkg->{'_FILE'} = shift : $pkg->{'_FILE'};  }
sub password { my $pkg = shift; @_ ? $pkg->{'_PASS'} = shift : $pkg->{'_PASS'};  }
sub options  { my $pkg = shift; @_ ? $pkg->{'_OPTIONS'} = @_ : $pkg->{'_OPTIONS'};  }


=item encrypt( PGP_Hex_Key )

Encrypts using PGP_Hex_Key (may be ommitted if $pkg->key was used previously
to set the recipient key).
The proper pgp key must exist on the calling users's keyring.

Returns true on sucess, undef on failure.

=back

=cut

sub encrypt {
    my $pkg = shift;
    my $pgp_key = $pkg->key( shift );
    my $pgp_bin = $pkg->bin;
    my $pgp_file = $pkg->file;
    my $pgp_out = $pkg->file . ".pgp";
    my @pgp_options = @{ $pkg->options };
    my @pgp_cmd = ();

    if ( not -f "$pgp_bin" ) { return $pkg->SUPER::oops( "$pgp_bin not found, please set it with pkg->bin()" ); }
    if ( not defined $pkg->key ) { return $pkg->SUPER::oops( "No key supplied for encrypt" ); }

    # Validate the key
    if ( system("$pgp_bin --quiet --list-key $pgp_key >/dev/null") != 0 ) {
        return $pkg->SUPER::oops( "$pgp_key is not a valid GnuPG key for this user." );
    }

    @pgp_cmd = "$pgp_bin @pgp_options --recipient $pgp_key --output $pgp_out --encrypt $pgp_file";
    if ( system( @pgp_cmd ) != 0 ) { return $pkg->SUPER::oops( "Error running @pgp_cmd" ) };

    return 1;
}

=over

=item decrypt( password [, newfile] )

Decrypts a pgp encrypted file using password (may omit if $pkg->password was
called previously to set the password).
The proper pgp key must exist on the calling users's keyring.

Returns true on sucess, undef on failure.

=cut

sub decrypt {
    my $pkg = shift;
    my $pgp_pass = $pkg->password( shift );
    my $pgp_file = $pkg->file;
    my $pgp_out  = shift;
    my $pgp_bin = q(/usr/bin/gpg);
    my @pgp_options = @{ $pkg->options };
    my @pgp_cmd = ();

    if ( not -f "$pgp_bin" ) { return $pkg->SUPER::oops( "$pgp_bin not found, please set it with pkg->bin()" ); }
    if ( not -f "$pgp_file" ) { return $pkg->SUPER::oops( "$pgp_file does not exist" ); }
    if ( not defined $pgp_pass ) { return $pkg->SUPER::oops( "No password supplied for decrypt" ); }

    if ( not defined $pgp_out ) { ( $pgp_out ) = ( $pgp_file =~ /(.*).pgp/ ); }

    @pgp_cmd = qq($pgp_bin @pgp_options --passphrase-fd 0 --output $pgp_out --decrypt $pgp_file);
    open PGP, "|@pgp_cmd > /dev/null 2>&1" or return $pkg->SUPER::oops( "Error running @pgp_cmd" );
    print PGP "$pgp_pass\n";
    close PGP;
    my $exitcode = ( $? >> 8 );
    return $pkg->SUPER::oops( "@pgp_cmd returned $exitcode") if $exitcode;

    return 1;
}

=back

=cut

##
## Start of FTP package
##
package DCY::Utils::FTP;
require Net::FTP;
require Net::SFTP;

use Cwd;
use File::Spec;
use Regexp::Shellish qw( :all );
our @ISA = qw( DCY::Utils );

=head1 FTP PACKAGE

=over

=item Constructor

$pkg = DCY::Utils::FTP->new( %FTP_HASH )

Returns an object initialized with an FTP Hash (see STRUCTURES above).
This will also open a connection to the URL provided.

returns undef and puts errors in the Error Queue if there were any problems.

=cut

#
#   Constructor
#
sub new {
    my $pkg = shift;
    my %opt = %{(shift)};

    my $host = $opt{'HOST'} if defined $opt{'HOST'} or return $pkg->SUPER::oops( "Must supply a HOST" );

    my $user = $opt{'USER'};
    my $pass = $opt{'PASS'};
    my $ldir = $opt{'LDIR'};
    my $rdir = $opt{'RDIR'};
    my $ren  = $opt{'RENAME'};

    my $sftp = defined $opt{'SFTP'}     ? 1                : 0;
    my $pasv = defined $opt{'PASV'}     ? 1                : 0;
    my $port = defined $opt{'PORT'}     ? $opt{'PORT'}     : 21;
    my $iden = defined $opt{'IDENTITY'} ? $opt{'IDENTITY'} : "$ENV{'HOME'}/.ssh/identity";

    my $obj = bless {
        '_HOST' => $host,      # HOST of server
        '_USER' => $user,      # The user to log in as
        '_PASS' => $pass,      # The password for user
        '_PASV' => $pasv,      # Use passive (1) or not (0)
        '_PORT' => $port,      # Connect on this port (default == 21)
        '_LDIR' => $ldir,      # The local directory to cd to first
        '_RDIR' => $rdir,      # The remote directory to cwd into
        '_SUFX' => $ren,       # If defined, rename files with this suffix
        '_SFTP' => $sftp,      # If true, use SFTP instead of FTP
        '_SSHI' => $iden,      # The SSH identity file to use (defaults to $HOME/.ssh/identity)
        '_FTPH' => undef,      # Stores our Net::(S)FTP handle (once connected)
    }, $pkg;

    $obj->connect or return $pkg->SUPER::oops( "Could not connect to " . $obj->host );

    return $obj;
}

#
# Descructor
#
sub DESTROY {
    my $pkg = shift;
    # Close our FTP session (if open)
    if ( defined $pkg->ftphandle ) {
        if ( $pkg->ftphandle =~ /::FTP/ ) { $pkg->ftphandle->quit; }
    }
}

#
# Methods
#

=item Methods

=over

=item $pkg->host : Returns or sets the HOST entry in the FTP Hash.

=item $pkg->user : Returns or sets the USER entry in the FTP Hash.

=item $pkg->pass : Returns or sets the PASS entry in the FTP Hash. (may also use $pkg->password)

Note:  You should call $pkg->reconnect if any of the above have changed.

=item $pkg->pasv : Returns or sets the PASV entry in the FTP Hash.

=item $pkg->port : Returns or sets the PORT entry in the FTP Hash.

=item $pkg->rdir : Returns or sets the RDIR entry in the FTP Hash.

=item $pkg->ldir : Returns or sets the LDIR entry in the FTP Hash.

=item $pkg->rename : Returns or sets the RENAME entry in the FTP Hash.

=item $pkg->reconnect : Forces a connection to the FTP server

=item $pkg->disconnect : Forces a the class to disconnect from the FTP server (?)

=back


=cut

sub host      { my $pkg = shift; @_ ? $pkg->{'_HOST'} = shift : $pkg->{'_HOST'};  }
sub user      { my $pkg = shift; @_ ? $pkg->{'_USER'} = shift : $pkg->{'_USER'}; }
sub pass      { my $pkg = shift; @_ ? $pkg->{'_PASS'} = shift : $pkg->{'_PASS'}; }
sub pasv      { my $pkg = shift; @_ ? $pkg->{'_PASV'} = shift : $pkg->{'_PASV'}; }
sub port      { my $pkg = shift; @_ ? $pkg->{'_PORT'} = shift : $pkg->{'_PORT'}; }
sub rdir      { my $pkg = shift; @_ ? $pkg->{'_RDIR'} = shift : $pkg->{'_RDIR'}; }
sub ldir      { my $pkg = shift; @_ ? $pkg->{'_LDIR'} = shift : $pkg->{'_LDIR'}; }
sub sftp      { my $pkg = shift; @_ ? $pkg->{'_SFTP'} = shift : $pkg->{'_SFTP'}; }
sub rename    { my $pkg = shift; @_ ? $pkg->{'_SUFX'} = shift : $pkg->{'_SUFX'};  }
sub ftphandle { my $pkg = shift; @_ ? $pkg->{'_FTPH'} = shift : $pkg->{'_FTPH'};  }
sub identity  { my $pkg = shift; @_ ? $pkg->{'_SSHI'} = shift : $pkg->{'_SSHI'};  }

# Aliases for Methods
sub password { shift->pass(@_); }
sub connect { shift->_connect; }
sub reconnect { shift->_connect(1); }
sub disconnect { shift->_connect(0); }
sub quit { shift->disconnect; }

=item Functions

=over

=cut

#
# Functions
#
sub _connect {
    my $pkg = shift;
    my $restart = shift;
    if ( defined $pkg->ftphandle ) {
        if ( $pkg->ftphandle =~ /::FTP/ ) {
            if ( defined $restart ) { $pkg->ftphandle->quit; }
            else { return $pkg->ftphandle; }
        }
    }

    if ( defined $restart and $restart == 0 ) { return $pkg->ftphandle( undef ); }
    if ( $pkg->sftp ) { return $pkg->ftphandle( $pkg->_open_sftp ); }
    return $pkg->ftphandle( $pkg->_open_ftp );
}

# _open_ftp
# 
#   Returns a Net::FTP object
#
sub _open_ftp {
    my $pkg = shift;
    my ( $ftp, $ldir, $rdir );

    if ( not defined $pkg->host ) { return $pkg->SUPER::oops( "Invalid HOST" ); }
    if ( not defined $pkg->user ) { return $pkg->SUPER::oops( "Invalid USER" ); }
    if ( not defined $pkg->pass ) { return $pkg->SUPER::oops( "Invalid PASS" ); }
    if ( not defined $pkg->port ) { $pkg->port(21); }
    if ( not defined $pkg->pasv ) { $pkg->pasv(0);  }

    # Open a connection to HOST
    $ftp = Net::FTP->new( $pkg->host, Timeout => 30, Port => $pkg->port, Passive => $pkg->pasv ) or
        return $pkg->SUPER::oops( "Unable to connect to " . $pkg->host );

    # Log in
    $ftp->login( $pkg->user, $pkg->pass ) or
        return $pkg->SUPER::oops( "Unable to authenticate to " . $pkg->user . '@' . $pkg->host . ": " . $ftp->message );

    $ftp->binary;  # Use binary mode

    # If we were provided with an LDIR, attempt to cwd to that directory.
    $ldir = $pkg->ldir;
    if ( defined $ldir and $ldir ne '' ) {
        chdir $ldir;
        if ( not cwd =~ /[\/]?$ldir[\/]?$/ ) {
            $pkg->SUPER::oops( "Problem trying to CWD to $ldir on the local machine." );
        }
    }
    $pkg->ldir( getcwd );

    # If we were provided with an RDIR, attempt to cwd to that directory.
    $rdir = $pkg->rdir;
    if ( defined $rdir and $rdir ne '' ) {
        $ftp->cwd( $rdir );
        if ( not $ftp->pwd =~ /[\/]?$rdir[\/]?$/ ) {
            $pkg->SUPER::oops( "Problem trying to CWD to $rdir on " . $pkg->host . ": " . $ftp->message );
        }
    }
    $pkg->rdir( $ftp->pwd );

    return $ftp;
}

# _open_sftp
# 
#   Returns a Net::SFTP object
#
sub _open_sftp {
    my $pkg = shift;
    my ( $sftp, $ldir, $rdir, %args );

    if ( not defined $pkg->host ) { return $pkg->SUPER::oops( "Invalid HOST" ); }

    $args{'warn'} = 1;
    $args{'ssh_args'} = [
        protocol => 2,
        identity_files => [ $pkg->identity ],
    ];
    if ( defined $pkg->user ) { $args{'user'} = $pkg->user; }
    if ( defined $pkg->pass ) { $args{'password'} = $pkg->pass; }

    # Open a connection to HOST
    $sftp = Net::SFTP->new( $pkg->host, %args )
        or return $pkg->SUPER::oops( "Unable to connect to " . $pkg->host );

    # If we were provided with an LDIR, attempt to cwd to that directory.
    $ldir = $pkg->ldir;
    if ( defined $ldir and $ldir ne '' ) {
        chdir $ldir;
        if ( not cwd =~ /[\/]?$ldir[\/]?$/ ) {
            $pkg->SUPER::oops( "Problem trying to CWD to $ldir on the local machine." );
        }
    }
    $pkg->ldir( getcwd );
    if ( not defined $pkg->rdir or $pkg->rdir eq '' ) { $pkg->rdir( '.' ); }

    return $sftp;
}

=item get( @files )

=item put( @files )

Transfers all files in the @Files list to either the current or remote
directory using the information in bookmark reference.

@Files is a standard list of files to retrieve and may include the absolute
path or a relative path.

Returns undef on error, 1 on success and > 1 if non-fatal errors were encountered
(e.g. Local file already exists).

=cut

sub get {
    my $pkg = shift;
    my @Files = @_;
    my @Valid_Files = ();
    my ( $file, $rtime, $rsize, $ltime, $lsize, $stat ) = ();
    my $exitcode = 1;   # Our exit counter.  We'll return > 1 if a non-fatal error occurred.

    # Make sure we're connected
    my $ftp = $pkg->ftphandle or return $pkg->SUPER::oops( "Not Connected to " . $pkg->host );

    # Validate our file list
    @Valid_Files = $pkg->ls( @Files );

    # Process each file in our array
    foreach $file ( @Valid_Files ) {

        # Get the size and modification time of the local file (if it exists)
        ( $lsize, $ltime ) = stat( $file ) ? (stat(_))[7,9] : (0,0);

        # Get the size and modification time of the remote file, issue an error and proceed
        # to the next file if it doesn't exist.
        if ( $ftp =~ /::FTP/ ) {
            $rtime = $ftp->mdtm($file)
                or return $pkg->SUPER::oops( "Could not get modification time for $file on " . $pkg->host . ": " . $ftp->message );

            $rsize = $ftp->size($file)
                or return $pkg->SUPER::oops( "Could not get size of $file on " . $pkg->host . ": " . $ftp->message );
        } else {    # SFTP
            $stat = $ftp->do_stat( $pkg->rdir . '/' . $file )
                or return $pkg->SUPER::oops( "Could not get files stats for $file on " . $pkg->host . ": " . $ftp->status );
            $rtime = $stat->mtime;
            $rsize = $stat->size;
        }

        # Check to be sure the remote file is different from the local file.
        if ( ( defined $rtime and defined $rsize )
               and ( ( $rtime >  $ltime )
               or  (   $rsize != $lsize ) ) ) {

            # Start the download.
            if ( $ftp =~ /::FTP/ ) {
                $ftp->get( $file )
                    or return $pkg->SUPER::oops( "Error retrieving $file: " . $ftp->message );
            } else {    # SFTP
                $ftp->get( $file, $file )
                    or return $pkg->SUPER::oops( "Error retrieving $file: " . $ftp->status );
            }

            if ( defined $pkg->rename ) {
                my $newFile = "$file" . $pkg->rename;
                if ( $ftp =~ /::FTP/ ) {
                    $ftp->rename( $file, $newFile )
                        or return $pkg->SUPER::oops( "Error renaming $file to $newFile: " . $ftp->message );
                } else {
                    $ftp->do_rename( $file, $newFile )
                        or return $pkg->SUPER::oops( "Error renaming $file to $newFile: " . $ftp->status );
                }
            }
        } else {
            $pkg->SUPER::oops( "Local file $file appears to be the same or newer than the remote, skipping download." );
            $exitcode++;
            next;
        }

    }
    return $exitcode;
}

sub put {
    my $pkg = shift;
    my @Files = @_;
    my @Valid_Files = ();
    my ( $file, $stat, $rtime, $rsize, $ltime, $lsize ) = ();
    my $exitcode = 1;   # Our exit counter.  We'll return > 1 if a non-fatal error occurred.

    # Get an open Net::FTP object or return undef.
    my $ftp = $pkg->ftphandle or return $pkg->SUPER::oops( "Not Connected to " . $pkg->host );

    # Validate our file list
    map { push @Valid_Files, glob } @Files;

    # Process each file in our array
    foreach $file ( @Valid_Files ) {
        # Get the size and modification time of the local file
        ( $lsize, $ltime ) = stat($file) ? (stat(_))[7,9] : (0,0);

        # Get the size and modification time of the remote file
        if ( $ftp =~ /::FTP/ ) {
            $rtime = $ftp->mdtm($file) or $rtime = 0;
            $rsize = $ftp->size($file) or $rsize = 0;
        } else {
            if ( $stat = $ftp->do_stat( $pkg->rdir . '/' . $file ) ) {
                $rtime = $stat->mtime or $rtime = 0;
                $rsize = $stat->size  or $rsize = 0;
            } else {
                $rtime = 0;
                $rsize = 0;
            }
        }

        # Check to be sure the local file is different from the remote file.
        if (    ( $ltime >  $rtime )
             or ( $lsize != $rsize ) ) {

            # Start the upload.
            if ( $ftp =~ /::FTP/ ) {
                $ftp->put($file)
                    or return $pkg->SUPER::oops( "Error uploading $file: " . $ftp->message );
            } else {
                $ftp->put($file, $pkg->rdir . '/' . $file )
                    or return $pkg->SUPER::oops( "Error uploading $file: " . $ftp->status );
            }

            if ( defined $pkg->rename ) {
                CORE::rename( $file, "$file" . $pkg->rename )
                    or return $pkg->SUPER::oops( "Error renaming $file to $file" . $pkg->rename . ": " . $ftp->message );
            }

        } else {
            $pkg->SUPER::oops( "The remote file $file appears to be the same or newer, skipping upload." );
            $exitcode++;
            next;
        }
    }
    return $exitcode;
}

=item ls( @filelist )
 
Validates the files given in @filelist and Returns an array of filenames
which exist on the server.

Returns undef on error.

=cut

sub ls {
    my $pkg = shift;
    my @Files = @_;
    my ( $file, @filelist, $stat, @statlist ) = ();

    # Make sure we're connected
    my $ftp = $pkg->ftphandle or return $pkg->SUPER::oops( "Not Connected to " . $pkg->host );

    # Check for valid files and/or patterns
    if ( $ftp =~ /::FTP/ ) {
        foreach $file ( $ftp->ls( @Files ) ) {
            if ( $ftp->size($file) ) {
                # Strip the path off the filename if any
                push @filelist, (File::Spec->splitpath( $file ))[2]; }
            else { $pkg->SUPER::oops( "$file not found on " . $pkg->host . $ftp->pwd ) }
        }
    } else {
        foreach $stat ( $ftp->ls( $pkg->rdir ) ) {
            foreach $file ( @Files ) {
                if ( shellish_glob( $file, $stat->{'filename'} ) ) {
                    push @filelist, $stat->{'filename'};
                }
            }
        }
    }

    # return the array (which may be empty).
    return sort @filelist;
}


=item list( @files )

Returns a reference to an array of long listings (ls -lg) of each file in
@Files or every file if @Files is empty or omitted.

@Files is a standard list of files to retrieve and may include the absolute
path or a relative path and shell patterns.

Returns undef on error or an array ref on success.

=cut

sub list {
    my $pkg = shift;
    my @Files = @_;
    my ( $ftp, $file, $stat, @statlist, @filelist ) = ();

    # Get an open Net::FTP object or return undef.
    $ftp = $pkg->ftphandle or return $pkg->SUPER::oops( "Not Connected to " . $pkg->host );

    # Fill our array with the remote listing or return undef
    if ( $ftp =~ /::FTP/ ) {
        @filelist = sort $ftp->dir( @Files ) or return $pkg->SUPER::oops( $ftp->message );
    } else {
        @statlist = $ftp->ls( $pkg->rdir );
        foreach $file ( $pkg->ls( @Files ) ) {
            foreach $stat ( @statlist ) {
                if ( $stat->{'filename'} eq $file ) { push @filelist, $stat->{'longname'}; }
            }
        }
    }

    # Add a carriage return on the end of each line
    map { s/$/\n/ } @filelist;

    # If we made it this far, return the listing.
    return @filelist;
}

=item is_ready( @files )

Checks a remote FTP site for any files that may still be changing.

This is useful when watching a remote FTP site for new files, it can
be used to be sure the transfer has completed on the remote end before
we download.

@Files is a standard list of files to retrieve and may include the absolute
path or a relative path.

Returns:
undef if there was an error.
0 if there were no files.
1 if the files are ready.
2 if files are still growing.

=back

=cut

sub is_ready {
    my $pkg = shift;
    my @Files = @_;
    my %ftp_file = ();
    my ( $file, $size, $stat );

    # Get an open Net::FTP object or return undef.
    my $ftp = $pkg->ftphandle or return $pkg->SUPER::oops( "Not Connected to " . $pkg->host );

    # Getting file list
    foreach $file ( $pkg->ls( @Files ) ) {
        if ( $ftp =~ /::FTP/ ) { $size = $ftp->size($file); }
        else { $size = $ftp->do_stat( $pkg->rdir . '/' . $file )->size; }
        $ftp_file{$file} = $size;
    }

    if ( not scalar keys %ftp_file ) { return $pkg->SUPER::oops( "No files found" ); }

    # Pause for a moment
    sleep 2;

    # Checking file sizes
    foreach $file ( keys %ftp_file ) {
        if (defined $ftp_file{$file} ) {
            if ( $ftp =~ /::FTP/ ) { $size = $ftp->size($file); }
            else { $size = $ftp->do_stat( $pkg->rdir . '/' . $file )->size; }

            if ( $ftp_file{$file} != $size ) {
                $pkg->SUPER::oops( "Transfer not complete for $file" );
                return 2;
            }
        }
    }

    # Return true if we've made it this far
    return 1;
}

=back

=head1 Bookmark CLASS

=over

=cut

##
## Start of Bookmark Package
##
package DCY::Utils::Bookmark;
use Carp;
our @ISA = qw( DCY::Utils );

# Accessor methods
sub file  { my $obj = shift; @_ ? $obj->{'_FILE'} = shift : $obj->{'_FILE'}; }

=item Methods

=over

=item Constructor

$pkg = DCY::Utils::Bookmark->new( $Bookmark_File )

=cut

sub new {
    my ( $pkg, $bookmark_file ) = @_;

    if ( ! -f $bookmark_file ) {
        $pkg->error("$bookmark_file does not exist");
        return;
    }

    bless {
        '_FILE'    => $bookmark_file,
    }, $pkg;
}

=item %hash = $pkg->get()

Retrives the contents of the bookamrk file and returns a hash of hashes
in the FTP Hash structure.

=cut

sub get {
    require MIME::Base64;

    my $bookmark = shift;
    my @bookmark_entries = @_;
    my $bookmark_version = 0;
    my $found = 0;              # Set to 1 if any entries are added
    my ( $ID, $URL, $User, $Pass, $RDir, $LDir, $Port, $hasPASV, $Comment ) = ();

    # Validate and open the bookmark file (must be defined with ->new beforehand)
    if ( not defined $bookmark->file() ) {
        $bookmark->error("Undefined bookmark file");
        return;
    }
    my $bookmark_file = $bookmark->file();
    open( BM, $bookmark_file ) or croak "Unable to open $bookmark_file:  $!";

    while( <BM> ) {
        chomp;

        # Look for the version of the bookmark file.
        if ( /^NcFTP bookmark-file version[:]?\s+(\d+)/i ) {
            $bookmark_version = $1;
            next;
        }

        # Skip this line
        next if /Number of bookmarks/;

        # Read our bookmark array
        my @bookmarks = ( split ',' );

        # Check for supported versions of the bookmark file (in case layout has changed).
        if ( $bookmark_version == 8 ) {
            next unless ( $ID, $URL, $User, $Pass, $RDir, $Port, $hasPASV, $Comment, $LDir ) = (@bookmarks)[0,1,2,3,5,7,11,14,21];
        } else {
            $bookmark->error("$bookmark_file is not a supported verion (this file is version $bookmark_version)");
            return;
        }

        # Apply pattern matching if we were given any.
        if ( @bookmark_entries ) {
            my $Found = 0;
            foreach my $Entry ( @bookmark_entries ) {
                if ( $ID =~ /$Entry/i ) { $Found = 1; }  # Got a hit
            }
            next unless $Found;
        }

        # Validate and assign defaults to critical items

        if ( $ID eq '' ) {              # No blank ID's
            $bookmark->error("Bookmark contains an invalid ID");
            next;
        }
        if ( $URL eq '' ) {             # No blank URL
            $bookmark->error("URL may not be blank, record skipped");
            next;
        }

        $User    = '' if not defined $User;
        $Pass    = '' if not defined $Pass;
        $RDir    = '' if not defined $RDir;
        $LDir    = '' if not defined $LDir;
        $Comment = '' if not defined $Comment;
        $Port    = 21 unless $Port;             # Default to port 21 if it's not set
        $hasPASV = 0  unless $hasPASV;          # Default to non-passive if it's not set

        $Pass =~ s/\*encoded\*//;               # Strip off the *encoded* portion of the password.
        $Pass = MIME::Base64::decode($Pass);    # Decrypt the password via simple Base64 decode.

        $bookmark->{$ID} = {
                'URL' => "$URL",
               'USER' => "$User",
               'PASS' => "$Pass",
               'RDIR' => "$RDir",
               'LDIR' => "$LDir",
               'PORT' => $Port,
               'PASV' => $hasPASV,
            'COMMENT' => "$Comment",
        };
        $found = 1;
    }

    return 1 if $found;
    return;
}

=item print()

Prints a report of all bookmarks in Bookmark Hash to STDOUT.  Useful for looking up bookmarks.

=back

=cut

sub print {
    my $obj = shift;

    if ( not %{$obj} ) {
        $obj->error('usage:  print_bookmarks( \%bookmark_hash );');
        return;
    }

    printf "%-25s %25s @ %s\n", "Bookmark ID", "User", "URL";
    print "~~~~~~~~~~~~~~~~~~~~~~~~~ ";
    print "~~~~~~~~~~~~~~~~~~~~~~~~~ ~ ";
    print "~~~~~~~~~~~~~~~~~~~~~~~~~\n";

    foreach my $ID ( sort keys %{$obj} ) {
        next unless defined %{$obj->{$ID}};
        printf "%-25s %25s @ %s\n", $ID, $obj->{$ID}{'USER'}, $obj->{$ID}{'URL'};
    }
}

1;

__END__

=back

=head1 EXAMPLES

=over

=item Bookmarks example

Prints the HOST associated with all bookmark entries in the file ".ncftp/bookmarks"

    #!/usr/bin/perl -w

    use DCY::Utils;

    my $Bookmark_OBJ = DCY::Utils::Bookmarks->new( '.ncftp/bookmarks' );
    my $Bookmarks = $Bookmark_OBJ->get;

    foreach my $Key ( sort keys %{$Bookmark} ) {
        print "The HOST for $Key is $Bookmark->{$Key}{'HOST'}\n";
    }

=item get_ftp example

Retrives all files ending in .pgp from /some/directory on the ftp.somedomain.com ftp site.

    #!/usr/bin/perl -w

    use DCY::Utils;

    my @filepattern = q(*.pgp);
    my %ftphash = (
        'HOST' => q(ftp.somedomain.com),
        'USER' => q(ftpuser),
        'PASS' => q(ftppassword),
        'RDIR' => q(/some/directory),
    );

    my $ftp = DCY::Utils::FTP->new( \%ftphash )
        or die $ftp->error;

    my $ready = $ftp->is_ready( @filepattern )
        or die $ftp->error;

    print "There aren't any files matching @filepattern\n" and exit if not $ready;

    foreach my $file ( $ftp->ls( @filepattern ) ) {
        $ftp->get( $file ) or die $ftp->error;

        # Print any non fatal messages that may be in the error queue
        # such as "file already exists".
        print map { "$_\n" } $ftp->error if $ftp->error_count;
    }


=back

=head1 SEE ALSO

This modules relies heavily on Net::FTP & Net::SCP to provide the core functionality.


=head1 AUTHOR

Donovan C. Young, E<lt>dyoung522@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008 by Donovan C. Young

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.5 or,
at your option, any later version of Perl 5 you may have available.


=cut

1;

