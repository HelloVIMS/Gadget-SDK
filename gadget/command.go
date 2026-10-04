package gadget

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hellovims/gadget-sdk/protocol"
)

// Command is something the host can ask the gadget to do.
type Command struct {
	// Name is dotted lowercase, e.g. "light.set" (PROTOCOL.md §6).
	Name string
	// Description tells the host's assistant what the command does.
	Description string
	// Risk is what running it can do; the host asks the owner before
	// running write and exec commands.
	Risk protocol.Risk
	// Input is a JSON Schema object for the input; nil means {"type":"object"}.
	Input json.RawMessage
	// Handler runs the command. Return a *protocol.RemoteError (see
	// protocol.Errorf) to choose the error code the host sees.
	Handler func(ctx context.Context, req *Request) (*Response, error)
}

// Request is one invocation of a command.
type Request struct {
	Command string
	Input   json.RawMessage
	Body    []byte
}

// Decode unmarshals the input into v, refusing unknown fields. An absent
// input decodes as {}. Failures are invalid_input errors.
func (r *Request) Decode(v any) error {
	in := r.Input
	if len(bytes.TrimSpace(in)) == 0 {
		in = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return protocol.Errorf(protocol.CodeInvalidInput, "%s: %v", r.Command, err)
	}
	return nil
}

// Response is a command's result: Output is marshalled as JSON
// (json.RawMessage passes through); Body carries raw bytes.
type Response struct {
	Output any
	Body   []byte
}

var defaultSchema = json.RawMessage(`{"type":"object"}`)

func (c Command) info() protocol.CommandInfo {
	in := c.Input
	if len(in) == 0 {
		in = defaultSchema
	}
	return protocol.CommandInfo{Name: c.Name, Description: c.Description, Risk: c.Risk.Normalize(), Input: in}
}

func buildCommands(cmds []Command) (map[string]Command, []protocol.CommandInfo, error) {
	byName := make(map[string]Command, len(cmds))
	infos := make([]protocol.CommandInfo, 0, len(cmds))
	for _, c := range cmds {
		if c.Handler == nil {
			return nil, nil, fmt.Errorf("gadget: command %s has no handler", c.Name)
		}
		if _, dup := byName[c.Name]; dup {
			return nil, nil, fmt.Errorf("gadget: command %s defined twice", c.Name)
		}
		info := c.info()
		if err := info.Validate(); err != nil {
			return nil, nil, err
		}
		byName[c.Name] = c
		infos = append(infos, info)
	}
	return byName, infos, nil
}

func runCommand(ctx context.Context, c Command, call *protocol.Call) (*protocol.Reply, error) {
	resp, err := c.Handler(ctx, &Request{Command: call.Command, Input: call.Input, Body: call.Body})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return &protocol.Reply{}, nil
	}
	reply := &protocol.Reply{Body: resp.Body}
	switch out := resp.Output.(type) {
	case nil:
	case json.RawMessage:
		reply.Output = out
	default:
		b, err := json.Marshal(out)
		if err != nil {
			return nil, errors.Join(protocol.Errorf(protocol.CodeFailed, "%s: output is not JSON-encodable", c.Name), err)
		}
		reply.Output = b
	}
	return reply, nil
}
