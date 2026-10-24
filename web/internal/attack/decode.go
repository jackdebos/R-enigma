package attack

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
)

// Decode requires explicit key knowledge (null means unknown), while settings
// alone are optional. Token parsing also rejects duplicate members at every depth.
func Decode(r io.Reader) (Input, *Issue) {
	var input Input
	d := json.NewDecoder(r)
	value, err := readValue(d)
	if err != nil {
		return input, issue("invalid_request", "", "Expected one attack JSON object.")
	}
	if _, err := d.Token(); err != io.EOF {
		return input, issue("invalid_request", "", "Unexpected trailing JSON.")
	}
	if problem := validateShape(value, reflect.TypeOf(input), ""); problem != nil {
		return input, problem
	}
	data, err := json.Marshal(value)
	if err == nil {
		err = json.Unmarshal(data, &input)
	}
	if err != nil {
		return Input{}, issue("invalid_request", "", "Invalid attack field type or integer.")
	}
	return input, nil
}

func readValue(d *json.Decoder) (any, error) {
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		obj := map[string]any{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("invalid key")
			}
			if _, exists := obj[name]; exists {
				return nil, fmt.Errorf("duplicate member")
			}
			value, err := readValue(d)
			if err != nil {
				return nil, err
			}
			obj[name] = value
		}
		_, err := d.Token()
		return obj, err
	case '[':
		values := []any{}
		for d.More() {
			value, err := readValue(d)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		_, err := d.Token()
		return values, err
	}
	return nil, fmt.Errorf("unexpected delimiter")
}

func validateShape(v any, t reflect.Type, path string) *Issue {
	bad := func(field string) *Issue {
		return issue("invalid_request", field, "Missing member or invalid field type.")
	}
	if v == nil {
		if path == "reflector" || strings.HasPrefix(path, "slots/") && (strings.HasSuffix(path, "/wheel") || strings.HasSuffix(path, "/ring") || strings.HasSuffix(path, "/position")) {
			return nil
		}
		return bad(path)
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		obj, ok := v.(map[string]any)
		if !ok {
			return bad(path)
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := f.Tag.Get("json")
			fields[name] = f.Type
			child := name
			if path != "" {
				child = path + "/" + name
			}
			value, present := obj[name]
			required := t == reflect.TypeOf(Input{}) && name != "settings" || t == reflect.TypeOf(InputSlot{}) || t == reflect.TypeOf(Plugboard{}) || t == reflect.TypeOf(Stage{}) && name == "pass"
			if !present {
				if required {
					return bad(child)
				}
				continue
			}
			if p := validateShape(value, f.Type, child); p != nil {
				return p
			}
		}
		for name := range obj {
			if _, ok := fields[name]; !ok {
				return issue("invalid_request", "", "Unknown attack member.")
			}
		}
	case reflect.Slice:
		array, ok := v.([]any)
		if !ok {
			return bad(path)
		}
		for i, value := range array {
			if p := validateShape(value, t.Elem(), path+"/"+strconv.Itoa(i)); p != nil {
				return p
			}
		}
	case reflect.Map:
		obj, ok := v.(map[string]any)
		if !ok {
			return bad(path)
		}
		for key, value := range obj {
			if p := validateShape(value, t.Elem(), path+"/"+key); p != nil {
				return p
			}
		}
	case reflect.String:
		if _, ok := v.(string); !ok {
			return bad(path)
		}
	case reflect.Bool:
		if _, ok := v.(bool); !ok {
			return bad(path)
		}
	case reflect.Int:
		n, ok := v.(float64)
		if !ok || n != float64(int(n)) {
			return bad(path)
		}
	}
	return nil
}
