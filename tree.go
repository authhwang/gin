// Copyright 2013 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// at https://github.com/julienschmidt/httprouter/blob/master/LICENSE

package gin

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// Param is a single URL parameter, consisting of a key and a value.
type Param struct {
	Key   string
	Value string
}

// Params is a Param-slice, as returned by the router.
// The slice is ordered, the first URL parameter is also the first slice value.
// It is therefore safe to read values by the index.
type Params []Param

// Get returns the value of the first Param which key matches the given name.
// If no matching Param is found, an empty string is returned.
func (ps Params) Get(name string) (string, bool) {
	for _, entry := range ps {
		if entry.Key == name {
			return entry.Value, true
		}
	}
	return "", false
}

// ByName returns the value of the first Param which key matches the given name.
// If no matching Param is found, an empty string is returned.
func (ps Params) ByName(name string) (va string) {
	va, _ = ps.Get(name)
	return
}

type methodTree struct {
	method string
	root   *node
}

type methodTrees []methodTree

func (trees methodTrees) get(method string) *node {
	for _, tree := range trees {
		if tree.method == method {
			return tree.root
		}
	}
	return nil
}

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}

func countParams(path string) uint8 {
	var n uint
	fmt.Println('1')
	for i := 0; i < len(path); i++ {
		if path[i] == ':' || path[i] == '*' {
			n++
		}
	}
	if n >= 255 {
		return 255
	}
	return uint8(n)
}

type nodeType uint8

const (
	static nodeType = iota // default
	root
	param
	catchAll
)

type node struct {
	path      string
	indices   string
	children  []*node
	handlers  HandlersChain
	priority  uint32
	nType     nodeType
	maxParams uint8
	wildChild bool
	fullPath  string
}

// increments priority of the given child and reorders if necessary.
//作用： 1.给新增得child根据priority排序 2.当出现child节点有新的child 需要重新排序
func (n *node) incrementChildPrio(pos int) int {
	n.children[pos].priority++
	prio := n.children[pos].priority

	// adjust position (move to front)
	newPos := pos
	for newPos > 0 && n.children[newPos-1].priority < prio {
		// swap node positions
		n.children[newPos-1], n.children[newPos] = n.children[newPos], n.children[newPos-1]

		newPos--
	}

	// build new index char string
	if newPos != pos {
		n.indices = n.indices[:newPos] + // unchanged prefix, might be empty
			n.indices[pos:pos+1] + // the index char we move
			n.indices[newPos:pos] + n.indices[pos+1:] // rest without char at 'pos'
	}

	return newPos
}

// addRoute adds a node with the given handle to the path.
// Not concurrency-safe!
/*
除了某些条件无法触发，基本上都跑通
0. 先获取与root.path公有的部分
1. 通常为第一个路由是第二个路由的静态延展时，则会选择截取余下不同的部分作为path，将其作为root的子节点进行添加处理。e.g. /user, /user/name
2. 通常公有部分只有'/'的短路由时，则会重新组织root节点，把旧root节点作为新子节点a, 子path为旧root除'/'余下部分的path，新子节点b相同处理。e.g. /user, /info
3. 通常先有一个长路由，后有一个短路由时，则会将旧root节点作为新子节点a，子path为旧root除相同部分外余下部分的path，新root节点为新添加节点。e.g. /user/info, /user (顺序的不同处理也不同)
4. 通常多层递进路由，例如/user, /user/:name, /user/:name/*action, 则在进入/user/:name, 会进入otherwise部分添加两个节点(子节点a，和子子节点b) a.path = / b.path = :name
当进入/user/:name/*action时, 因为root.indices = '/'，所以进入next bype bath部分, 对子节点a的priority++, 将node n = a, 重新run walk section。
这时候的path = /:name/*action，n.path = / 相同部分为/, 进入 make new child section， 因为n.wildChild = true，所以需要检查是否有相同的:name部分，检查成功则 重新run walk section
这时候的path = :name/*action, n.path = :name， 截取余下不同部分/*action， 进入otherwise insert section，b.indices += '/'，添加子子子节点c,子子子子节点d, 子子子子子节点e, c.path="" c.indice=/ , d.path="", e.path="/*action"

/user/:name, /user/info 不允许同时出现，因为有了通配符路由不允许相同部分静态路由

有indices的改变通常都是由连续两个节点生成时

bug:
/user, /user/:name, /user/:name/*action, /user/:name/*action/*bug 这种情况下会出现最后一个路由没有拦截成功，因为在调用addRoute检查是否含有更长通配符时不严密， 所以通过条件检查。
/user, /user/:name, /user/:name/*action/ 只有这样才能在条件检查下找到，因为不允许*action节点后面含有/


*/
func (n *node) addRoute(path string, handlers HandlersChain) {
	fullPath := path
	n.priority++
	//累计有多少个路由参数 例如/user/:name/*action,其中:name是require，*action是optional
	numParams := countParams(path)
	//&{  [] [] %!s(uint32=1) %!s(gin.nodeType=0) %!s(uint8=0) %!s(bool=false)}
	// &{/user/  [%!s(*gin.node=&{:name  [] [0x98b1b0 0x98be60 0x98dd00] 1 2 1 false})] [] %!s(uint32=2) %!s(gin.nodeType=1) %!s(uint8=0) %!s(bool=true)}
	parentFullPathIndex := 0

	// non-empty tree
	if len(n.path) > 0 || len(n.children) > 0 {
	walk:
		for {
			// Update maxParams of the current node
			if numParams > n.maxParams {
				n.maxParams = numParams
			}

			// Find the longest common prefix.
			// This also implies that the common prefix contains no ':' or '*'
			// since the existing key can't contain those chars.
			i := 0
			max := min(len(path), len(n.path))
			for i < max && path[i] == n.path[i] {
				i++
			}

			// Split edge
			if i < len(n.path) {
				child := node{
					path:      n.path[i:],
					wildChild: n.wildChild,
					indices:   n.indices,
					children:  n.children,
					handlers:  n.handlers,
					priority:  n.priority - 1,
					fullPath:  n.fullPath,
				}

				// Update maxParams (max of all children)
				for i := range child.children {
					if child.children[i].maxParams > child.maxParams {
						child.maxParams = child.children[i].maxParams
					}
				}

				n.children = []*node{&child}
				// []byte for proper unicode char conversion, see #65
				n.indices = string([]byte{n.path[i]})
				n.path = path[:i]
				n.handlers = nil
				n.wildChild = false
				n.fullPath = fullPath[:parentFullPathIndex+i]
			}

			// Make new node a child of this node
			if i < len(path) {
				path = path[i:]

				if n.wildChild {
					//代表有一个通配符子节点，不允许同时拥有多个通配符子节点或者静态节点
					parentFullPathIndex += len(n.path)
					n = n.children[0]
					//TODO: 针对相同顺序路由节点增加priority是有必要，若不是时候捏？
					//answer: 不是相同的 会panic
					n.priority++

					// Update maxParams of the child node
					if numParams > n.maxParams {
						n.maxParams = numParams
					}
					numParams--

					// Check if the wildcard matches
					//通配符在相同的前缀下只能有一个 /user/:name /user/:info /user/action不能共存
					//只允许相同前缀的路由扩展新的后代节点 /user/:name /user/:name/*action
					//检查通配符时会导致因/user/:name/*action, /user/:name/*action/*bug这种情况导致增加*action

					//2019.12.23 发现是逻辑问题，应该是项目开始至今都没觉得这样会有问题
					if len(path) >= len(n.path) && n.path == path[:len(n.path)] {
						// check for longer wildcard, e.g. :name and :names
						if len(n.path) >= len(path) || path[len(n.path)] == '/' {
							continue walk
						}
					}

					pathSeg := path
					if n.nType != catchAll {
						pathSeg = strings.SplitN(path, "/", 2)[0]
					}
					prefix := fullPath[:strings.Index(fullPath, pathSeg)] + n.path
					panic("'" + pathSeg +
						"' in new path '" + fullPath +
						"' conflicts with existing wildcard '" + n.path +
						"' in existing prefix '" + prefix +
						"'")
				}

				c := path[0]

				// slash after param
				// 作用父节点是param 子节点的path = ''的节点处理
				if n.nType == param && c == '/' && len(n.children) == 1 {
					parentFullPathIndex += len(n.path)
					n = n.children[0]
					n.priority++
					continue walk
				}

				// Check if a child with the next path byte exists
				for i := 0; i < len(n.indices); i++ {
					if c == n.indices[i] {
						parentFullPathIndex += len(n.path)
						i = n.incrementChildPrio(i)
						n = n.children[i]
						continue walk
					}
				}

				// Otherwise insert it
				if c != ':' && c != '*' {
					// []byte for proper unicode char conversion, see #65
					n.indices += string([]byte{c})
					child := &node{
						maxParams: numParams,
						fullPath:  fullPath,
					}
					n.children = append(n.children, child)
					n.incrementChildPrio(len(n.indices) - 1)
					n = child
				}
				n.insertChild(numParams, path, fullPath, handlers)
				return

			} else if i == len(path) { // Make node a (in-path) leaf
				if n.handlers != nil {
					panic("handlers are already registered for path '" + fullPath + "'")
				}
				n.handlers = handlers
			}
			return
		}
	} else { // Empty tree
		n.insertChild(numParams, path, fullPath, handlers)
		n.nType = root
	}
}

// 如果是/user 则root.path = /user
// 如果是/user/:name 则root节点的path = /user/, 其child是通配符节点b，b.path = :name
// 如果是/user/:name/action 则root节点的path = /user/, 其child是通配符节点b，b.path = :name/action
// 如果是/user/:name/*action 则root.path = /user/, 其child是通配符节点b，b.path = :name, b.child是catchall节点c, c.path='', c.child是catchall节点d, d.path=/*action
// // 如果是/user/:name/info/*action 则root.path = /user/, 其child是通配符节点b，b.path = :name, b.child是catchall节点c, c.path='/info', c.child是catchall节点d, d.path=/*action
func (n *node) insertChild(numParams uint8, path string, fullPath string, handlers HandlersChain) {
	var offset int // already handled bytes of the path

	// find prefix until first wildcard (beginning with ':' or '*')
	for i, max := 0, len(path); numParams > 0; i++ {
		c := path[i]
		if c != ':' && c != '*' {
			continue
		}

		// find wildcard end (either '/' or path end)
		//获取通配符结尾的index（包括'/'）
		end := i + 1
		for end < max && path[end] != '/' {
			switch path[end] {
			// the wildcard name must not contain ':' and '*'
			case ':', '*':
				panic("only one wildcard per path segment is allowed, has: '" +
					path[i:] + "' in path '" + fullPath + "'")
			default:
				end++
			}
		}

		// check if this Node existing children which would be
		// unreachable if we insert the wildcard here
		// 跟上述的一样: 只能拥有一个通配符子节点，不允许同时拥有多个通配符子节点或者静态节点
		if len(n.children) > 0 {
			panic("wildcard route '" + path[i:end] +
				"' conflicts with existing children in path '" + fullPath + "'")
		}

		// check if the wildcard has a name
		//*a/ 包括/或者结束index
		if end-i < 2 {
			panic("wildcards must be named with a non-empty name in path '" + fullPath + "'")
		}

		if c == ':' { // param
			// split path at the beginning of the wildcard
			if i > 0 {
				n.path = path[offset:i]
				offset = i
			}

			child := &node{
				nType:     param,
				maxParams: numParams,
				fullPath:  fullPath,
			}
			n.children = []*node{child}
			n.wildChild = true
			n = child
			n.priority++
			numParams--

			// if the path doesn't end with the wildcard, then there
			// will be another non-wildcard subpath starting with '/'
			if end < max {
				//结尾不包含 '/'
				n.path = path[offset:end]
				offset = end

				child := &node{
					maxParams: numParams,
					priority:  1,
					fullPath:  fullPath,
				}
				n.children = []*node{child}
				n = child
			}

		} else { // catchAll
			//推测 *通配符只能适用于路由的最后一位 不存在/user/:name/*action/:when
			if end != max || numParams > 1 {
				panic("catch-all routes are only allowed at the end of the path in path '" + fullPath + "'")
			}

			if len(n.path) > 0 && n.path[len(n.path)-1] == '/' {
				panic("catch-all conflicts with existing handle for the path segment root in path '" + fullPath + "'")
			}

			// currently fixed width 1 for '/'
			i--
			//检查通配符的前一位是否被'/'分隔
			if path[i] != '/' {
				panic("no / before catch-all in path '" + fullPath + "'")
			}

			n.path = path[offset:i]
			//会用双重node拦截，第一种情况当出现*action为空时，则以*前和:通配符后面之间的作为静态路由拦截 e.g. /user/:name/info/*action时就是/info，则用第一个node拦截，若不是.则用第二个node拦截

			// first node: catchAll node with empty path
			child := &node{
				wildChild: true,
				nType:     catchAll,
				maxParams: 1,
				fullPath:  fullPath,
			}
			n.children = []*node{child}
			n.indices = string(path[i])
			n = child
			n.priority++

			// second node: node holding the variable
			child = &node{
				path:      path[i:],
				nType:     catchAll,
				maxParams: 1,
				handlers:  handlers,
				priority:  1,
				fullPath:  fullPath,
			}
			n.children = []*node{child}

			return
		}
	}

	// insert remaining path part and handle to the leaf
	// 对上个节点把剩下的路径补充
	n.path = path[offset:]
	n.handlers = handlers
	n.fullPath = fullPath
}

// nodeValue holds return values of (*Node).getValue method
type nodeValue struct {
	handlers HandlersChain
	params   Params
	tsr      bool
	fullPath string
}

// getValue returns the handle registered with the given path (key). The values of
// wildcards are saved to a map.
// If no handle can be found, a TSR (trailing slash redirect) recommendation is
// made if a handle exists with an extra (without the) trailing slash for the
// given path.

//先检查路由长度与当前长度:
//若比n.path长，且与n.path相同，若是，则判断是否有通配符子节点，若无，则继续寻找余下子节点索引是否有跟当前path相同，有则代表有后面的子节点对应 重跑walk；
//若有通配符节点params，则先获取第一个子节点并指向n，获取对应的key和value，放入params，如果该路由还有后续内容，则继续往下走，若无，则检查n是否有handler register ，有register，就返回甘节点，没有注册，则寻找其子节点看看能不能做重定向
//若有通配符节点catchall，则先获取第一个子节点，获取对应的key和value，不检查是否有hanlder的情况下直接返回该节点

//若比n.path长，但没有与n.path相同, 则检查path是否等于 / 或者 e.g. n.path = /name/b && path = /name && n.handler != nil 若其中一个条件符合，则重定向

//若与n.path相同，若n.handler ！= nil，返回该节点，若条件a(暂时不理解是什么情况下)符合，则重定向，若条件b(根据索引，寻找余下子节点，若有与path相同，则重定向)
func (n *node) getValue(path string, po Params, unescape bool) (value nodeValue) {
	value.params = po
walk: // Outer loop for walking the tree
	for {
		if len(path) > len(n.path) {
			// 针对/user /user/ , /user /user/name
			if path[:len(n.path)] == n.path {
				path = path[len(n.path):]
				// If this node does not have a wildcard (param or catchAll)
				// child,  we can just look up the next child node and continue
				// to walk down the tree
				if !n.wildChild {
					c := path[0]
					for i := 0; i < len(n.indices); i++ {
						if c == n.indices[i] {
							n = n.children[i]
							continue walk
						}
					}

					// Nothing found.
					// We can recommend to redirect to the same URL without a
					// trailing slash if a leaf exists for that path.
					value.tsr = path == "/" && n.handlers != nil
					return
				}

				// handle wildcard child
				n = n.children[0]
				switch n.nType {
				case param:
					// find param end (either '/' or path end)
					end := 0
					for end < len(path) && path[end] != '/' {
						end++
					}

					// save param value
					if cap(value.params) < int(n.maxParams) {
						value.params = make(Params, 0, n.maxParams)
					}
					i := len(value.params)
					//将路由参数传进params
					value.params = value.params[:i+1] // expand slice within preallocated capacity
					value.params[i].Key = n.path[1:]
					val := path[:end]
					if unescape {
						var err error
						if value.params[i].Value, err = url.QueryUnescape(val); err != nil {
							value.params[i].Value = val // fallback, in case of error
						}
					} else {
						value.params[i].Value = val
					}

					// we need to go deeper!
					//如果在end 小于 path
					if end < len(path) {
						if len(n.children) > 0 {
							path = path[end:]
							n = n.children[0]
							continue walk
						}

						// ... but we can't
						value.tsr = len(path) == end+1
						return
					}

					//当前节点n 有 handlers时
					if value.handlers = n.handlers; value.handlers != nil {
						value.fullPath = n.fullPath
						return
					}
					//如果符合当前节点路由，但他没有注册任何handlers时
					if len(n.children) == 1 {
						// No handle found. Check if a handle for this path + a
						// trailing slash exists for TSR recommendation

						//那就将当前路由加'/'，并看它有没有handlers
						n = n.children[0]
						value.tsr = n.path == "/" && n.handlers != nil
					}

					return

				case catchAll:
					// save param value
					if cap(value.params) < int(n.maxParams) {
						value.params = make(Params, 0, n.maxParams)
					}
					i := len(value.params)
					value.params = value.params[:i+1] // expand slice within preallocated capacity
					//在添加catchall的节点path 一定是以/开头
					value.params[i].Key = n.path[2:]
					if unescape {
						var err error
						if value.params[i].Value, err = url.QueryUnescape(path); err != nil {
							value.params[i].Value = path // fallback, in case of error
						}
					} else {
						value.params[i].Value = path
					}

					value.handlers = n.handlers
					value.fullPath = n.fullPath
					return

				default:
					panic("invalid node type")
				}
			}
		} else if path == n.path {
			// We should have reached the node containing the handle.
			// Check if this node has a handle registered.

			//path与root.path相同，而且root path 有handler
			if value.handlers = n.handlers; value.handlers != nil {
				value.fullPath = n.fullPath
				return
			}

			if path == "/" && n.wildChild && n.nType != root {
				value.tsr = true
				return
			}

			// No handle found. Check if a handle for this path + a
			// trailing slash exists for trailing slash recommendation
			for i := 0; i < len(n.indices); i++ {
				if n.indices[i] == '/' {
					n = n.children[i]
					value.tsr = (len(n.path) == 1 && n.handlers != nil) ||
						(n.nType == catchAll && n.children[0].handlers != nil)
					return
				}
			}

			return
		}

		// Nothing found. We can recommend to redirect to the same URL with an
		// extra trailing slash if a leaf exists for that path
		value.tsr = (path == "/") ||
			(len(n.path) == len(path)+1 && n.path[len(path)] == '/' &&
				path == n.path[:len(n.path)-1] && n.handlers != nil)
		return
	}
}

// findCaseInsensitivePath makes a case-insensitive lookup of the given path and tries to find a handler.
// It can optionally also fix trailing slashes.
// It returns the case-corrected path and a bool indicating whether the lookup
// was successful.
func (n *node) findCaseInsensitivePath(path string, fixTrailingSlash bool) (ciPath []byte, found bool) {
	ciPath = make([]byte, 0, len(path)+1) // preallocate enough memory

	// Outer loop for walking the tree
	for len(path) >= len(n.path) && strings.EqualFold(path[:len(n.path)], n.path) {
		path = path[len(n.path):]
		ciPath = append(ciPath, n.path...)

		if len(path) > 0 {
			// If this node does not have a wildcard (param or catchAll) child,
			// we can just look up the next child node and continue to walk down
			// the tree
			if !n.wildChild {
				r := unicode.ToLower(rune(path[0]))
				for i, index := range n.indices {
					// must use recursive approach since both index and
					// ToLower(index) could exist. We must check both.
					if r == unicode.ToLower(index) {
						out, found := n.children[i].findCaseInsensitivePath(path, fixTrailingSlash)
						if found {
							return append(ciPath, out...), true
						}
					}
				}

				// Nothing found. We can recommend to redirect to the same URL
				// without a trailing slash if a leaf exists for that path
				found = fixTrailingSlash && path == "/" && n.handlers != nil
				return
			}

			n = n.children[0]
			switch n.nType {
			case param:
				// find param end (either '/' or path end)
				k := 0
				for k < len(path) && path[k] != '/' {
					k++
				}

				// add param value to case insensitive path
				ciPath = append(ciPath, path[:k]...)

				// we need to go deeper!
				if k < len(path) {
					if len(n.children) > 0 {
						path = path[k:]
						n = n.children[0]
						continue
					}

					// ... but we can't
					if fixTrailingSlash && len(path) == k+1 {
						return ciPath, true
					}
					return
				}

				if n.handlers != nil {
					return ciPath, true
				} else if fixTrailingSlash && len(n.children) == 1 {
					// No handle found. Check if a handle for this path + a
					// trailing slash exists
					n = n.children[0]
					if n.path == "/" && n.handlers != nil {
						return append(ciPath, '/'), true
					}
				}
				return

			case catchAll:
				return append(ciPath, path...), true

			default:
				panic("invalid node type")
			}
		} else {
			// We should have reached the node containing the handle.
			// Check if this node has a handle registered.
			if n.handlers != nil {
				return ciPath, true
			}

			// No handle found.
			// Try to fix the path by adding a trailing slash
			if fixTrailingSlash {
				for i := 0; i < len(n.indices); i++ {
					if n.indices[i] == '/' {
						n = n.children[i]
						if (len(n.path) == 1 && n.handlers != nil) ||
							(n.nType == catchAll && n.children[0].handlers != nil) {
							return append(ciPath, '/'), true
						}
						return
					}
				}
			}
			return
		}
	}

	// Nothing found.
	// Try to fix the path by adding / removing a trailing slash
	if fixTrailingSlash {
		if path == "/" {
			return ciPath, true
		}
		if len(path)+1 == len(n.path) && n.path[len(path)] == '/' &&
			strings.EqualFold(path, n.path[:len(path)]) &&
			n.handlers != nil {
			return append(ciPath, n.path...), true
		}
	}
	return
}
