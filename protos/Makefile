icebox.pb.c: icebox.proto
	../vendor/nanopb/generator-bin/protoc --nanopb_out=. --java_out=. icebox.proto

nanopb.pb.c: nanopb.proto
	../vendor/nanopb/generator-bin/protoc --nanopb_out=. --java_out=. nanopb.proto

icebox.pb.go: icebox.proto
	protoc icebox.proto --go_out=plugins=grpc:.
