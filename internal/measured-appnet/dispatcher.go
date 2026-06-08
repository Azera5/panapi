// Copyright 2021 Thorben Krüger (thorben.krueger@ovgu.de)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package measured_appnet

import (
	"context"
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	// "github.com/scionproto/scion/go/lib/sock/reliable"
)

type TimedPacketDispatcherService struct {
	Dispatcher  reliable.Dispatcher
	SCMPHandler snet.SCMPHandler
}

func (s *TimedPacketDispatcherService) Register(ctx context.Context, ia addr.IA,
	registration *net.UDPAddr, svc addr.SVC) (snet.PacketConn, uint16, error) {

	rconn, port, err := s.Dispatcher.Register(ctx, ia, registration, svc)
	if err != nil {
		return nil, 0, err
	}
	return &TimedSCIONPacketConn{
		conn:        rconn,
		scmpHandler: s.SCMPHandler,
	}, port, nil
}
