// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.6.1
// source: plugins/clicommand/clicommand.proto

package cli

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// CLICommandClient is the client API for CLICommand service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CLICommandClient interface {
	// Sends a greeting
	Command(ctx context.Context, in *CLIArgs, opts ...grpc.CallOption) (*CLIResponse, error)
}

type cLICommandClient struct {
	cc grpc.ClientConnInterface
}

func NewCLICommandClient(cc grpc.ClientConnInterface) CLICommandClient {
	return &cLICommandClient{cc}
}

func (c *cLICommandClient) Command(ctx context.Context, in *CLIArgs, opts ...grpc.CallOption) (*CLIResponse, error) {
	out := new(CLIResponse)
	err := c.cc.Invoke(ctx, "/clicommand.CLICommand/Command", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CLICommandServer is the server API for CLICommand service.
// All implementations must embed UnimplementedCLICommandServer
// for forward compatibility
type CLICommandServer interface {
	// Sends a greeting
	Command(context.Context, *CLIArgs) (*CLIResponse, error)
	mustEmbedUnimplementedCLICommandServer()
}

// UnimplementedCLICommandServer must be embedded to have forward compatible implementations.
type UnimplementedCLICommandServer struct {
}

func (UnimplementedCLICommandServer) Command(context.Context, *CLIArgs) (*CLIResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Command not implemented")
}
func (UnimplementedCLICommandServer) mustEmbedUnimplementedCLICommandServer() {}

// UnsafeCLICommandServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CLICommandServer will
// result in compilation errors.
type UnsafeCLICommandServer interface {
	mustEmbedUnimplementedCLICommandServer()
}

func RegisterCLICommandServer(s grpc.ServiceRegistrar, srv CLICommandServer) {
	s.RegisterService(&CLICommand_ServiceDesc, srv)
}

func _CLICommand_Command_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CLIArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CLICommandServer).Command(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/clicommand.CLICommand/Command",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CLICommandServer).Command(ctx, req.(*CLIArgs))
	}
	return interceptor(ctx, in, info, handler)
}

// CLICommand_ServiceDesc is the grpc.ServiceDesc for CLICommand service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CLICommand_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "clicommand.CLICommand",
	HandlerType: (*CLICommandServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Command",
			Handler:    _CLICommand_Command_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "plugins/clicommand/clicommand.proto",
}
