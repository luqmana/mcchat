use extra::json;
use std::util;

struct ExtraJSON(json::Json);

impl ExtraJSON {
    pub fn new(j: json::Json) -> ExtraJSON {
        ExtraJSON(j)
    }

    pub fn string(&self) -> ~str {
        match **self {
            json::String(ref s) => s.clone(),
            _ => fail!("tried to get string from non-string")
        }
    }

    pub fn list(&self) -> ~[ExtraJSON] {
        self.list_map(util::id)
    }

    pub fn list_map<T>(&self, f: &fn(ExtraJSON) -> T) -> ~[T] {
        match **self {
            json::List(ref l) => {
                l.map(|x| f(ExtraJSON(x.clone())))
            }
            _ => fail!("tried to get list from non-list")
        }
    }

    pub fn as_int(&self) -> int {
        match **self {
            json::Number(f) => f as int,
            _ => fail!("tried to get int from non-number")
        }
    }
}

trait ExtraJSONIndex {
    fn index(&self, j: &ExtraJSON) -> ExtraJSON;
}

impl<'a> ExtraJSONIndex for &'a str {
    fn index(&self, j: &ExtraJSON) -> ExtraJSON {
        match **j {
            json::Object(ref ij) => {
                match ij.find(&self.to_owned()) {
                    Some(jj) => ExtraJSON(jj.clone()),
                    None => fail!("no such key")
                }
            }
            _ => fail!("tried to index non-object with string")
        }
    }
}

impl ExtraJSONIndex for int {
    fn index(&self, j: &ExtraJSON) -> ExtraJSON {
        match **j {
            json::List(ref l) => ExtraJSON(l[*self].clone()),
            _ => fail!("tried to index non-list with int")
        }
    }
}

impl<T: ExtraJSONIndex> Index<T, ExtraJSON> for ExtraJSON {
    fn index(&self, idx: &T) -> ExtraJSON {
        idx.index(self)
    }
}
