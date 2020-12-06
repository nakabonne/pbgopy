// Copyright 2020 The PipeCD Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cache provides an interface to temporarily
// store content on a pbgopy server.
package cache

import "errors"

var ErrNotFound = errors.New("not found")

// Getter wraps a method to read from cache.
type Getter interface {
	Get(key interface{}) (interface{}, error)
}

// Putter wraps a method to write to cache.
type Putter interface {
	Put(key interface{}, value interface{}) error
}

// Deleter wraps a method to delete from cache.
type Deleter interface {
	Delete(key interface{}) error
}

// Cache groups Getter, Putter and Deleter.
type Cache interface {
	Getter
	Putter
	Deleter
}
