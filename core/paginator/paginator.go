package paginator

func GetTotalPages(total, limit uint32) uint32 {
	p := total / limit
	if total % limit == 0 {
		return p
	} else {
		return p+1
	}
}

func IsFirstPage(total, limit, offset uint32) bool {
	if (offset < total) && (offset <= limit) {
		return true
	}
	return false
}

func IsLastPage(total, limit, offset uint32) bool {
	if offset >= total {
		return true
	}
	return false
}

func IsOnePage(total, limit, offset uint32) bool {

	if IsFirstPage(total, limit, offset) && IsLastPage(total, limit, offset) {
		return true
	}
	return false
}

func HaveNext(total, limit, offset uint32) bool {
	//p := GetTotalPages(total, limit)
	if (offset < total) && (offset + limit < total) {
		return true
	}
	if IsLastPage(total, limit, offset) {
		// last page
		return false
	}
	return true
}
