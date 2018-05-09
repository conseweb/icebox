package paginator

import (
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestPaginator(t *testing.T) {
	Convey(`Paginator test`, t, func() {
		x := HaveNext(4, 4, 1)
		So(x, ShouldEqual, true)
		x = HaveNext(4, 4, 2)
		So(x, ShouldEqual, true)
		x = HaveNext(4, 4, 3)
		So(x, ShouldEqual, true)
		x = HaveNext(4, 4, 4)
		So(x, ShouldEqual, false)
		x = HaveNext(5, 4, 4)
		So(x, ShouldEqual, true)
		x = HaveNext(8, 4, 4)
		So(x, ShouldEqual, true)
		x = HaveNext(8, 9, 8)
		So(x, ShouldEqual, false)
	})
}

func TestGetTotalPages(t *testing.T) {
	Convey(`GetTotalPages test`, t, func() {
		x := GetTotalPages(31, 4)
		So(x, ShouldEqual, 8)
		x = GetTotalPages(4, 3)
		So(x, ShouldEqual, 2)
		x = GetTotalPages(4, 4)
		So(x, ShouldEqual, 1)
		x = GetTotalPages(15, 7)
		So(x, ShouldEqual, 3)
	})
}

func TestIsFirstPage(t *testing.T) {
	Convey(`GetTotalPages test`, t, func() {
		x := IsFirstPage(31, 4, 4)
		So(x, ShouldEqual, true)
		x = IsFirstPage(15, 8, 8)
		So(x, ShouldEqual, true)
		x = IsFirstPage(14, 7, 8)
		So(x, ShouldEqual, false)
		x = IsFirstPage(15, 5, 10)
		So(x, ShouldEqual, false)
	})
}