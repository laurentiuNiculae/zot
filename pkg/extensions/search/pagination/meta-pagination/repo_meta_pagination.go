package pagination

import (
	"fmt"
	"sort"

	zerr "zotregistry.io/zot/errors"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/search/pagination"
	mTypes "zotregistry.io/zot/pkg/meta/types"
)

type RepoMetaPageFinder struct {
	limit      int
	offset     int
	sortBy     pagination.SortCriteria
	pageBuffer []mTypes.RepoMeta
}

func NewRepoMetaPageFinder(limit, offset int, sortBy pagination.SortCriteria) (*RepoMetaPageFinder, error) {
	if sortBy == "" {
		sortBy = pagination.AlphabeticAsc
	}

	if limit < 0 {
		return nil, zerr.ErrLimitIsNegative
	}

	if offset < 0 {
		return nil, zerr.ErrOffsetIsNegative
	}

	if _, found := RepoMetaSortFuncs()[sortBy]; !found {
		return nil, fmt.Errorf("sorting repos by '%s' is not supported %w",
			sortBy, zerr.ErrSortCriteriaNotSupported)
	}

	return &RepoMetaPageFinder{
		limit:      limit,
		offset:     offset,
		sortBy:     sortBy,
		pageBuffer: []mTypes.RepoMeta{},
	}, nil
}

func (pf *RepoMetaPageFinder) Add(repoMeta mTypes.RepoMeta) {
	pf.pageBuffer = append(pf.pageBuffer, repoMeta)
}

func (pf *RepoMetaPageFinder) Page() ([]mTypes.RepoMeta, zcommon.PageInfo) {
	if len(pf.pageBuffer) == 0 {
		return []mTypes.RepoMeta{}, zcommon.PageInfo{}
	}

	pageInfo := zcommon.PageInfo{}

	sort.Slice(pf.pageBuffer, RepoMetaSortFuncs()[pf.sortBy](pf.pageBuffer))

	// the offset and limit are calculated in terms of repos counted
	start := pf.offset
	end := pf.offset + pf.limit

	// we'll return an empty array when the offset is greater than the number of elements
	if start >= len(pf.pageBuffer) {
		start = len(pf.pageBuffer)
		end = start
	}

	if end >= len(pf.pageBuffer) {
		end = len(pf.pageBuffer)
	}

	page := pf.pageBuffer[start:end]

	pageInfo.ItemCount = len(page)

	if start == 0 && end == 0 {
		page = pf.pageBuffer
		pageInfo.ItemCount = len(page)
	}

	pageInfo.TotalCount = len(pf.pageBuffer)

	return page, pageInfo
}

func RepoMetaSortFuncs() map[pagination.SortCriteria]func(pageBuffer []mTypes.RepoMeta) func(i, j int) bool {
	return map[pagination.SortCriteria]func(pageBuffer []mTypes.RepoMeta) func(i, j int) bool{
		pagination.AlphabeticAsc: RepoMetaSortByAlphabeticAsc,
		pagination.AlphabeticDsc: RepoMetaSortByAlphabeticDsc,
		pagination.Relevance:     RepoMetaSortByRelevance,
		pagination.UpdateTime:    RepoMetaSortByUpdateTime,
		pagination.Downloads:     RepoMetaSortByDownloads,
	}
}

func RepoMetaSortByAlphabeticAsc(pageBuffer []mTypes.RepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].Name < pageBuffer[j].Name
	}
}

func RepoMetaSortByAlphabeticDsc(pageBuffer []mTypes.RepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].Name > pageBuffer[j].Name
	}
}

func RepoMetaSortByRelevance(pageBuffer []mTypes.RepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].Rank < pageBuffer[j].Rank
	}
}

// SortByUpdateTime sorting descending by time.
func RepoMetaSortByUpdateTime(pageBuffer []mTypes.RepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		if pageBuffer[i].LastUpdatedImage == nil || pageBuffer[i].LastUpdatedImage.LastUpdated == nil {
			return false
		}

		if pageBuffer[j].LastUpdatedImage == nil || pageBuffer[j].LastUpdatedImage.LastUpdated == nil {
			return false
		}

		return pageBuffer[i].LastUpdatedImage.LastUpdated.After(*pageBuffer[j].LastUpdatedImage.LastUpdated)
	}
}

// SortByDownloads returns a comparison function for descendant sorting by downloads.
func RepoMetaSortByDownloads(pageBuffer []mTypes.RepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].DownloadCount > pageBuffer[j].DownloadCount
	}
}
