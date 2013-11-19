use extra::json;

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

    pub fn list<T>(&self, f: &fn(&ExtraJSON) -> T) -> ~[T] {
        match **self {
            json::List(ref l) => {
                l.map(|x| ExtraJSON(x.clone())).map(f)
            }
            _ => fail!("tried to get list from non-list")
        }
    }
}

trait ExtraJSONIndex {
    fn index(&self, j: &ExtraJSON) -> ExtraJSON;
}

impl ExtraJSONIndex for &'static str {
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

impl ExtraJSONIndex for ~str {
    fn index(&self, j: &ExtraJSON) -> ExtraJSON {
        match **j {
            json::Object(ref ij) => {
                match ij.find(self) {
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
