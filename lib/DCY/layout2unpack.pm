
=pod

=head1 USAGE

layout2unpack - Converts mtc_jcl layout file to perl's unpack template.

Returns an array containing:
record length (integer),
unpack template (string),
and field names (array).

  Example:

      my $Input;
      my %Records;
      my ( $RecordLength, $Template, @Fields ) = layout2unpack( layout_file );

      open( FILE, "<input_file" ) or die "Unable to open input file: $!\n";
      until( eof( FILE ) ) {
          read( FILE, $Input, $RecordLength ) == $RecordLength or die "Problem in read\n";
          my @Records{@Fields} = unpack( $Template, $Input );
          # At this point, the hash %Records contains each field name as the key and data in the value.
          # do something with it.
      }
      close( FILE );

=cut

use strict;

package DCY::layout2unpack;

use base 'Exporter';
our @EXPORT = ( 'layout2unpack' );

sub layout2unpack {
    my $FileName = shift;
    my $Template;
    my $RecordLength;
    my @Layout;
    my @Fields;
    my $Pos;
    my $NextPos = 1;
    my ( $got_layout, $got_begin );

    open LAYOUT, "<$FileName" or die( "Unable to open $FileName: $!\n" );

    while( <LAYOUT> ) {
        if ( /record length:\s+(\d+)/ ) { $RecordLength = $1; };

        if ( /layout/ ) { $got_layout = 1; }
        next unless defined $got_layout;

        if ( /begin/ ) { $got_begin = 1; }
        next unless defined $got_begin;

        my ( $Field, $Start, $Length, $Type ) = /(\w+)[\(\d,\d,\w\)]*\s+(\d+)\s+(\d+)\s+([A-Z])/ or next;

        push @Layout,
            {
                'FIELD'  => $Field,
                'START'  => $Start,
                'LENGTH' => $Length,
                'TYPE'   => $Type,
            };

        if ( /end$/ ) { last; }
    }
    close LAYOUT;

    foreach my $Layout ( @Layout ) {
        next unless defined $Layout->{START};

        $Pos = $Layout->{START};

        if ( $Pos != $NextPos ) { $Template .= ( "x" . ( $Pos - $NextPos ) . " " ); }
        $Template .= ( "A" . $Layout->{LENGTH} . " " );

        push @Fields, $Layout->{FIELD};

        $NextPos = ( $Pos + $Layout->{LENGTH} );
    }

    if ( $Template ) { return ( $RecordLength, $Template, @Fields ); }
    return undef;
}

1;
