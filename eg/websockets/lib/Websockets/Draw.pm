package Websockets::Draw;

use strict;
use warnings;
no  warnings 'uninitialized';
use bytes;

use Nginx;
use Digest::SHA1 qw(sha1_base64);
use Here::Template;
use JSON::XS;

sub parse_ws_frames_v13 ($$);
sub append_ws_frame_v13 ($$);


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


my %clients;

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

    my $rbuf;
    my $wbuf = "HTTP/1.1 101 Switching Protocols"  ."\x0d\x0a".
               "Upgrade: websocket"                ."\x0d\x0a".
               "Connection: Upgrade"               ."\x0d\x0a".
               "Sec-WebSocket-Accept: $wsaccept"   ."\x0d\x0a".
               ""                                  ."\x0d\x0a";

    ngx_writer $c, $wbuf, 60, sub {
        if (!$!) {
            $wbuf = '';
            return NGX_READ;
        } else {
            delete $clients{$c};
            $r->give_connection;
            $r->finalize_request(NGX_DONE);
            return NGX_NOOP;
        }
    };

    ngx_reader $c, $rbuf, 0, 0, 60, sub {
        if (!$!) {
            my @frames;
            my $len = parse_ws_frames_v13 $rbuf, \@frames;

            if ($len) {
                $rbuf = substr $rbuf, $len;
                foreach (@frames) {
                    next if $_->[1] eq 'pong';

                    if ($_->[1] eq 'ping') {
                        $_->[1] = 'pong';
                        append_ws_frame_v13 $_, $wbuf;
                    } elsif ($_->[1] eq 'text') {
                        my $x;
                        eval {  $x = decode_json ${$_->[2]};  };

                        if (ref $x eq 'ARRAY') {
                            if ($x->[0] eq 'cpoint') {
                                next  if ref $x->[1] ne 'ARRAY';
                                $x->[1]->[2] = "$c";
                            }

                            # broadcasting message
                            foreach my $d (keys %clients) {
                                next  if $c eq $d;

                                append_ws_frame_v13 
                                    ['fin', 'text', encode_json $x], 
                                    ${$clients{$d}};
                                ngx_write $d;
                            }
                        }
                    }
                }
                return NGX_READ;
            } elsif (defined $len && length($rbuf) < 262144) {
                return NGX_READ;
            } else {
                # broadcasting disconnect
                foreach my $d (keys %clients) {
                    next  if $c eq $d;

                    append_ws_frame_v13 
                        ['fin', 'text', encode_json ['cdisconnect', ["$c"]]], 
                        ${$clients{$d}};
                    ngx_write $d;
                }

                delete $clients{$c};
                $r->give_connection;
                $r->finalize_request(NGX_DONE);
                return NGX_NOOP;
            }
        } else {
            # broadcasting disconnect
            foreach my $d (keys %clients) {
                next  if $c eq $d;

                append_ws_frame_v13 
                    ['fin', 'text', encode_json ['cdisconnect', ["$c"]]], 
                    ${$clients{$d}};
                ngx_write $d;
            }

            delete $clients{$c};
            $r->give_connection;
            $r->finalize_request(NGX_DONE);
            return NGX_NOOP;
        }
    };

    $clients{$c} = \$wbuf;
    ngx_write $c; 

    return NGX_DONE;
}


sub webpage_handler {
    my ($r) = @_;
    my $buf;
    $r->main_count_inc; 

    my $prefix = $r->location_name;  $prefix =~ s/\/$//;

$buf = <<'TMPL';
<!doctype html>
<html>
<style type="text/css"><!--

    * { margin: 0; padding: 0; }

    html,body,#container { width: 100%; height: 100%; }

    body { background: #228800; }

    #container { position: relative; overflow: hidden;  }
    #canvas { position: absolute; top: 0; left: 0; }

    .pointblock { line-height: 1px; width: 5px; height: 5px;
                  background: yellow; }

--></style>
<body id="body">
<div id="container">
    <canvas id="canvas" width="200" height="200">
    </canvas>
</div>
<script language="javascript" type="text/javascript"><!--

    var d  = window.document;
    var ct = d.getElementById("container");
    var c  = d.getElementById("canvas");
    var cx = c.getContext("2d"); 

    c.width  = window.screen.width;
    c.height = window.screen.height;

    var ws;
    var wsUri = "ws://<?= $r->variable('http_host')."$prefix/websocket" ?>";
 

    /* queue until websocket is avaialbe, 
       (should be easy to implement reconnect with this) */

    var q = new Array(); 

    function send (cmd, args) {
        var msg = "[" + "\"" + cmd + "\", [";
        for (var i = 0; i < args.length; i++) {
            msg += "\"" + args[i] + "\"";
            if (i < args.length - 1) {  msg += ", ";  }
        }
        msg += "]]";

        if (ws && ws.readyState == 1) {
            ws.send(msg);
        } else {
            q.push(msg);
        }
    }

    window.setInterval(function () {
        if (ws && ws.readyState == 1) {
            for (var i = 0; i < q.length; i++) {
                ws.send(q[i]);
            }
            q = new Array();
        } 
    }, 500);


    /* ops */

    var xx;
    var yy;

    cx.strokeStyle = "#ffffff";
    cx.lineJoin = "round";
    cx.lineWidth = 2;

    function cclear (z) {
        cx.fillStyle = "#228800";
        cx.fillRect(0, 0, c.width, c.height);
    }

    function cline (z) {
        cx.beginPath();
        cx.moveTo(z[0], z[1]);
        cx.lineTo(z[2], z[3]);
        cx.stroke();
        cx.closePath();
    }

    var pointers = new Object();

    function cpoint (z) {
        var x  = z[0];
        var y  = z[1];
        var id = z[2];
        var ptr;

        if (pointers[id]) {
            ptr = pointers[id];
        } else {
            ptr = d.createElement("div"); 
            ptr.className = 'pointblock';
            ptr.style.position = 'absolute';
            ptr.style.display = 'block';
            ptr.style.zIndex = '100';
            ptr.innerHTML = '&nbsp;'; 
            ct.appendChild(ptr); 
            pointers[id] = ptr;
        }

        ptr.style.left = x + 'px';
        ptr.style.top  = y + 'px';
    }

    function cdisconnect (z) {
        var id = z[0];
        var ptr;

        if (pointers[id]) {
            ptr = pointers[id];
            ct.removeChild(ptr);
            delete pointers[id];
        }
    }

    var cops = new Object();
    cops["cclear"]      = cclear;
    cops["cline"]       = cline;
    cops["cpoint"]      = cpoint;
    cops["cdisconnect"] = cdisconnect;


    /* mouse events */

    var mdown = 0;

    function mousedown (ev) {
        var x = ev.pageX;
        var y = ev.pageY;

        ev.preventDefault();

        if (ev.which && ev.which != 1) {
            return;
        }

        if (x > 5 || y > 5) {
            mdown = 1;
            xx = x;
            yy = y;
        } else {
            cclear([]);
            send("cclear", []);
        }
    }

    function mousemove (ev) {
        var x = ev.pageX;
        var y = ev.pageY;

        ev.preventDefault();

        if (mdown) {
            cline([xx, yy, x, y]);
            send("cline", [xx, yy, x, y]);
            xx = x;
            yy = y;
        } else {
            send("cpoint", [x, y]);
        }
    }

    function mouseup (ev) {
        var x = ev.pageX;
        var y = ev.pageY;

        ev.preventDefault();

        if (mdown) {
            mdown = 0;
            send("cline", [xx, yy, x, y]);
        }
    }

    window.addEventListener('mousedown', mousedown, false);
    window.addEventListener('mousemove', mousemove, false);
    window.addEventListener('mouseup',   mouseup,   false);


    /* websocket */

    ws = new WebSocket(wsUri);

    ws.onmessage = function (ev) { 
        eval("var p = " + ev.data + ";");

        if (cops[p[0]]) {
            cops[p[0]](p[1]);
        }
    };


    /* event generator for load testing */
/*
    window.setTimeout(function () {
        window.setInterval(function () {
            send("cpoint", [ Math.floor(Math.random() * 100),
                             Math.floor(Math.random() * 500) ]);
        }, 10);
    }, 1000 + Math.floor(Math.random() * 1000)); // jitter
*/



//--></script>
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

 

my %WSOPCODES = (
    0  => 'continue',
    1  => 'text',
    2  => 'binary',
    8  => 'close',
    9  => 'ping',
    10 => 'pong'
);

my %WSTOOPCODE = map { $WSOPCODES{$_} => $_ } keys %WSOPCODES;


sub parse_ws_frames_v13 ($$) {
    my ($buf, $out) = (\$_[0], $_[1]);
    my $total = 0;

    while (length($$buf) - $total >= 2) {
        my ($c0, $c1) = unpack "CC", substr($$buf, $total, 2);
        my $hlen = 2;
        my $fin = ($c0 & 0x80) >> 7;
        my $opcode = $c0 & 0x0f;

        my $len = $c1 &~ 0x80;
        if ($len == 126) {
            last if length($$buf) - $total < 4;
            ($len) = unpack "n", substr($$buf, $total + 2, 2);
            $hlen += 4;
        } elsif ($len == 127) {
            last if length($$buf) - $total < 10;
            ($len) = unpack "N", substr($$buf, $total + 6, 4);
            $hlen += 10;
        }

        my $mask;
        if ($c1 & 0x80) {
            last if length($$buf) - $total < $hlen + 4;
            $mask = substr $$buf, $total + $hlen, 4;  $hlen += 4;
        }

        last          if length($$buf) - $total - $hlen < $len;  # read more
        return undef  if !exists $WSOPCODES{$opcode};  # error

        my $payload = substr($$buf, $total + $hlen, $len);
        if ($mask) {
            for (my $i = 0; $i < $len; $i++) {
                my $j  = $i % 4;
                my $in = substr $payload, $i, 1; 
                my $m  = substr $mask, $j, 1;
                substr $payload, $i, 1, $in ^ $m;
            }
        }

        push @$out, [ 
            ($fin ? 'fin' : ''), 
            $WSOPCODES{$opcode}, 
            \$payload
        ];

        $total += $hlen + $len;
    }

    return $total;
}


sub append_ws_frame_v13 ($$) {
    my ($frame, $buf) = ($_[0], \$_[1]);
    my $payload;

    if (defined $frame->[2]) {
        if (ref $frame->[2] eq 'SCALAR') {
            $payload = $frame->[2];
        } elsif (ref $frame->[2] eq '') {
            $payload = \$frame->[2];
        } else {
            return undef;
        }
    } else {
        $payload = \"";
    }

    my ($c0, $c1);
    my $total = 0;

    my $fin = $frame->[0];

    return undef if !exists $WSTOOPCODE{$frame->[1]};
    my $opcode = $WSTOOPCODE{$frame->[1]};

    my $h;

    $c0  = $opcode;
    $c0  = $c0 | 0x80  if $fin;

    $h .= pack "C", $c0;

    if (length($$payload) < 126) {
        $c1 = length($$payload);
        $h .= pack "C", $c1;
    } elsif (length($$payload) <= 0xffff) {
        $c1  = 126;
        $h .= pack "C", $c1;
        $h .= pack "n", length($$payload);
    } else {
        $c1  = 127;
        $h .= pack "C", $c1;
        $h .= pack "x4N", length($$payload);
    }

    $$buf .= $h;
    $total += length $h;

    for (my $i = 0; $i < length($$payload); $i++) {
        my $in = substr $$payload, $i, 1; 
        $$buf .= $in;
        $total += 1;
    }

    return $total;
}


1;
