// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.6.1
// source: pkg/plugins/scan/scan.proto

package scan

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

// ScanClient is the client API for Scan service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ScanClient interface {
	// Sends a greeting
	Scan(ctx context.Context, in *ScanRequest, opts ...grpc.CallOption) (*ScanResponse, error)
}

type scanClient struct {
	cc grpc.ClientConnInterface
}

func NewScanClient(cc grpc.ClientConnInterface) ScanClient {
	return &scanClient{cc}
}

func (c *scanClient) Scan(ctx context.Context, in *ScanRequest, opts ...grpc.CallOption) (*ScanResponse, error) {
	out := new(ScanResponse)
	err := c.cc.Invoke(ctx, "/scan.Scan/Scan", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ScanServer is the server API for Scan service.
// All implementations must embed UnimplementedScanServer
// for forward compatibility
type ScanServer interface {
	// Sends a greeting
	Scan(context.Context, *ScanRequest) (*ScanResponse, error)
	mustEmbedUnimplementedScanServer()
}

// UnimplementedScanServer must be embedded to have forward compatible implementations.
type UnimplementedScanServer struct {
}

func (UnimplementedScanServer) Scan(context.Context, *ScanRequest) (*ScanResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Scan not implemented")
}
func (UnimplementedScanServer) mustEmbedUnimplementedScanServer() {}

// UnsafeScanServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ScanServer will
// result in compilation errors.
type UnsafeScanServer interface {
	mustEmbedUnimplementedScanServer()
}

func RegisterScanServer(s grpc.ServiceRegistrar, srv ScanServer) {
	s.RegisterService(&Scan_ServiceDesc, srv)
}

func _Scan_Scan_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ScanRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ScanServer).Scan(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/scan.Scan/Scan",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ScanServer).Scan(ctx, req.(*ScanRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Scan_ServiceDesc is the grpc.ServiceDesc for Scan service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Scan_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "scan.Scan",
	HandlerType: (*ScanServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Scan",
			Handler:    _Scan_Scan_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "pkg/plugins/scan/scan.proto",
}
