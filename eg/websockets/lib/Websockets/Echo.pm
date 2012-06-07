package Websockets::Echo;

use strict;
use warnings;
no  warnings 'uninitialized';
use bytes;

use Nginx;
use Digest::SHA1 qw(sha1_base64);
use Here::Template;


sub handler {
    my ($r) = @_;

    my $prefix = $r->location_name;  $prefix =~ s/\/$//;
    my $uri    = $r->uri;

    if ($uri eq "$prefix/websocket") {
        return &websocket_handler;
    } elsif ($uri eq "$prefix/") {
        return &webpage_handler;
    } else {
        return 404;
    }
}


sub websocket_handler {
    my ($r) = @_;
    $r->main_count_inc; 

    if (lc($r->header_in('upgrade')) ne 'websocket' || 
        $r->header_in('sec-websocket-version') ne '13') 
    {
        $r->finalize_request(501);
        return NGX_DONE;
    }

    if (lc($r->header_in('origin')) ne 
            "http://".lc($r->variable('http_host'))) {
        $r->finalize_request(403);
        return NGX_DONE;
    }

    my $wsaccept = (sha1_base64 $r->header_in('sec-websocket-key')
                                ."258EAFA5-E914-47DA-95CA-C5AB0DC85B11")."=";

    my $c = $r->take_connection;

    my $buf = "HTTP/1.1 101 Switching Protocols"  ."\x0d\x0a".
              "Upgrade: websocket"                ."\x0d\x0a".
              "Connection: Upgrade"               ."\x0d\x0a".
              "Sec-WebSocket-Accept: $wsaccept"   ."\x0d\x0a".
              ""                                  ."\x0d\x0a";

    ngx_writer $c, $buf, 5, sub {
        if (!$!) {
            $buf = '';
            return NGX_READ;
        } else {
            $r->give_connection;
            $r->finalize_request(NGX_DONE);
            return NGX_NOOP;
        }
    };

    my( @connections );

    ngx_reader $c, $buf, 0, 0, 5, sub {
        if (!$!) {
            # echoing everything back
            if( !defined( $connections[ $c ] ) ) {
                my( $payload_len, $masked, $mask, $payload, $offset );
                $masked = vec( $buf, 15, 1 );
                $payload_len = vec( $buf, 1, 8 ) & 127;
                $offset = 2;
                if( $payload_len == 126 ) {
                    ( $payload_len ) = unpack "n", substr( $buf, $offset, 2 );
                    $offset += 2;
                } elsif( $payload_len == 127 ) {
                    ( $payload_len ) = unpack "N", substr( $buf, $offset + 4, 4 );
                    $offset += 8;
                }
                if( $masked ) {
                    $mask = substr( $buf, $offset, 4 );
                    $offset += 4;
                }
                $payload = substr( $buf, $offset, $payload_len );
                my $reminder;
                if( $masked ) {
                    if( length( $payload ) < $payload_len ) {
                        $reminder = substr( $payload, -( length( $payload ) % 4 ) );
                        $payload = substr( $payload, 0, -( length( $payload ) % 4 ) );
                    }
                    $payload = _mask( $payload, $mask );
                    vec( $buf, 15, 1 ) = 0;
                }
                $buf = substr( $buf, 0, $offset - 4 ) . $payload;
                if( defined $reminder || length( $payload ) < $payload_len ) {
                    $connections[ $c ] = { total => $payload_len, written => length( $payload ),
                        masked => $masked, mask => $mask, reminder => $reminder };
                }
            } else {
                if( $connections[ $c ]->{ masked } ) {
                    if( defined $connections[ $c ]->{ reminder } ) {
                        $buf = $connections[ $c ]->{ reminder } . $buf;
                    }
                    if( length( $buf ) + $connections[ $c ]->{ written } < $connections[ $c ]->{ total } ) {
                        $connections[ $c ]->{ reminder } = substr( $buf, -( length( $buf ) % 4 ) );
                        $buf = substr( $buf, 0, -( length( $buf ) % 4 ) );
                    }
                    $buf = _mask( $buf, $connections[ $c ]->{ mask } );
                }
                $connections[ $c ]->{ written } += length( $buf );
                if( $connections[ $c ]->{ written } >= $connections[ $c ]->{ total } ) {
                    delete $connections[ $c ];
                }
            }
            return NGX_WRITE; 
        } else {
            $r->give_connection;
            $r->finalize_request(NGX_DONE);
            return NGX_NOOP;
        }
    };

    ngx_write $c; 

    return NGX_DONE;  # always after $r->main_count_inc
}

sub _mask {
    my( $payload, $mask ) = @_;

    my @mask = split //, $mask;

    my @payload = split //, $payload;
    for( my $i = 0; $i < @payload; $i++ ) {
        my $j = $i % 4;
        $payload[$i] ^= $mask[$j];
    }
    return join '', @payload;
}

sub webpage_handler {
    my ($r) = @_;
    my $buf;
    $r->main_count_inc; 

    my $prefix = $r->location_name;  $prefix =~ s/\/$//;

$buf = <<'TMPL';
<!doctype html>
<html>
<script language="javascript" type="text/javascript"><!--

    var ws;
    var wsUri = "ws://<?= $r->variable('http_host')."$prefix/websocket" ?>";
    
    function start () { 
        ws = new WebSocket(wsUri);

        ws.onopen = function (ev) {
            log("ONOPEN:");
            log("    sending 'hello'");
            ws.send("hello");
        };

        ws.onmessage = function (ev) { 
            log("ONMESSAGE:");
            log("    '" + ev.data + "'");
            ws.close();
        };

        ws.onclose = function (ev) { 
            log("ONCLOSE:");
        };

        ws.onerror = function (ev) { 
            log("ONERROR:");
            log("    '" + ev.data + "'");
        }; 
    }

    function log (message) { 
        var pre = document.createElement("span"); 
        pre.innerHTML = message + "\n"; 
        document.getElementById("log").appendChild(pre); 
    }

//--></script>

<body onload="start()">
    <pre id="log"></pre>
</body>

</html>
TMPL

    $r->header_out('Cache-Control',  'no-cache');
    $r->header_out('Pragma',         'no-cache');
    $r->header_out('Content-Length', length($buf));

    $r->send_http_header('text/html; charset=UTF-8');

    $r->print($buf)
        unless $r->header_only;

    $r->send_special(NGX_HTTP_LAST);
    $r->finalize_request(NGX_OK);

    return NGX_DONE;  # always after $r->main_count_inc
}


1;

