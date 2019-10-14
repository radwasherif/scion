package snet

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/appconf"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
)

var _ net.PacketConn = (*ConnWrapper)(nil)
var _ net.Conn = (*ConnWrapper)(nil)
var _ Conn = (*ConnWrapper)(nil)

type ConnWrapper struct {
	conn *SCIONConn
	conf *appconf.AppConf
}

func NewConnWrapper(c Conn, conf *appconf.AppConf) *ConnWrapper {
	cw := ConnWrapper{conn: c.(*SCIONConn), conf: conf}
	return &cw
}

func (c *ConnWrapper) Read(b []byte) (int, error) {
	return c.conn.Read(b)
}

func (c *ConnWrapper) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.conn.ReadFrom(b)
}

func (c *ConnWrapper) ReadFromSCION(b []byte) (int, *Addr, error) {
	return c.conn.ReadFromSCION(b)
}

func (c *ConnWrapper) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *ConnWrapper) WriteTo(b []byte, raddr net.Addr) (int, error) {
	sraddr, ok := raddr.(*Addr)
	if !ok {
		return 0, common.NewBasicError("Unable to write to non-SCION address", nil, "addr", raddr)
	}

	return c.WriteToSCION(b, sraddr)
}

func (c *ConnWrapper) WriteToSCION(b []byte, address *Addr) (int, error) {
	return c.write(b, address)
}

func (c *ConnWrapper) write(b []byte, address *Addr) (int, error) {
	resolver := c.conn.resolver.pathResolver
	localIA := c.conn.resolver.localIA
	var key spathmeta.PathKey = ""
	remoteAddr := address.Copy()
	var nextHop *overlay.OverlayAddr
	var path *spath.Path
	var err error
	//resolver called with empty context and not timeout enforcement for now
	if c.conf.PathSelection().IsStatic() {
		staticNextHop, staticPath := c.conf.GetStaticPath()
		//if we're using a static path, query resolver only if this is the first call to write
		if staticNextHop == nil && staticPath == nil {
			nextHop, path, err = resolver.GetFilter(context.Background(), localIA, address.IA, c.conf.Policy(), &key)
			if err != nil {
				return 0, common.NewBasicError("Writer: Error resolving address: ", err)
			}
			c.conf.SetStaticPath(nextHop, path)
		} else if staticNextHop != nil && staticPath != nil {
			nextHop, path = staticNextHop, staticPath
		} else {
			return 0, common.NewBasicError("Next hop and path must both be either defined or undefine", nil)
		}

	} else if c.conf.PathSelection().IsArbitrary() {
		nextHop, path, err = resolver.GetFilter(context.Background(), localIA, address.IA, c.conf.Policy(), &key)
		if err != nil {
			return 0, common.NewBasicError("Writer: Error resolving address: ", err)
		}
	} else {
		return 0, common.NewBasicError("Path selection option not yet supported", nil)
	}
	remoteAddr.NextHop, remoteAddr.Path = nextHop, path
	return c.conn.writeWithLock(b, remoteAddr)

}

func (c *ConnWrapper) Close() error {
	return c.conn.Close()
}

func (c *ConnWrapper) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *ConnWrapper) BindAddr() net.Addr {
	return c.conn.BindAddr()
}
func (c *ConnWrapper) SVC() addr.HostSVC {
	return c.conn.SVC()
}
func (c *ConnWrapper) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}
func (c *ConnWrapper) SetDeadline(deadline time.Time) error {
	return c.conn.SetDeadline(deadline)
}
func (c *ConnWrapper) SetReadDeadline(deadline time.Time) error {
	return c.conn.SetReadDeadline(deadline)
}

func (c *ConnWrapper) SetWriteDeadline(deadline time.Time) error {
	return c.conn.SetWriteDeadline(deadline)
}
