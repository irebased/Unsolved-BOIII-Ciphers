/// Exact first-layer inventory, stopping before transform/codec/layer 2/oracle.
#[derive(Args)]
pub struct PrefixInventoryArgs {
    /// Canonical target access is disabled unless explicitly supplied.
    #[arg(long)] pub run_target: bool,
    /// New JSON output; existing output and temp files are refused.
    #[arg(long)] pub output: std::path::PathBuf,
}
const PI_KEYS:[&str;6]=["ZOMBIE","ZOMBIES","Zombie","Zombies","zombie","zombies"];
const PI_MODES:[&str;7]=["cbc","cfb","ecb","ncfb","nofb","ofb","stream"];
const PI_KDS:[&str;4]=["natural","null-pad-max","null-pad-next-supported","repeat-pad-max"];
const PI_IVS:[&str;2]=["ascii0","null"];
const PI_PRES:[&str;3]=["identity","reverse","reverse_words"];
const PI_PRIMS:[&str;16]=["DES","RC2","RC4","Blowfish","Blowfish-compat","Twofish","Serpent","Rijndael-256","AES","XTEA","Loki97","Saferplus","3DES","CAST-128","IDEA","Salsa20"];

fn pi_args()->SweepArgs { SweepArgs {
 target:"rev7".into(),tier:vec!["t3".into()],prims:None,
 modes:PI_MODES.iter().map(|x|x.to_string()).collect(),keys:PI_KEYS.iter().map(|x|x.to_string()).collect(),
 kd:PI_KDS.iter().map(|x|x.to_string()).collect(),ivs:PI_IVS.iter().map(|x|x.to_string()).collect(),
 xf:vec!["identity".into()],pre:PI_PRES.iter().map(|x|x.to_string()).collect(),post:vec!["identity".into()],
 codec:vec!["identity".into()],toolfmt:vec!["none".into()],variants:"recorded".into(),variant_label:Some("hex-exact".into()),
 oracle:"printable-0.75".into(),max_candidates:None,progress_every:0.0,dry_run:false,max_hits:0,emit_claim:None,
}}
fn pi_hist(data:&[u8])->Vec<u64>{let mut h=vec![0;256];for &b in data{h[b as usize]+=1;}h}
fn pi_write_new(path:&Path,value:&serde_json::Value)->Result<()> {
 anyhow::ensure!(!path.exists(),"refusing existing output {}",path.display());let tmp=path.with_extension("tmp");
 anyhow::ensure!(!tmp.exists(),"refusing existing temp {}",tmp.display());std::fs::write(&tmp,serde_json::to_vec(value)?)?;
 std::fs::rename(tmp,path)?;Ok(())
}
fn pi_inventory(raw:String,id:&str)->Result<serde_json::Value>{
 let target=crate::corpus::Target{id:id.into(),raw,display:ra_core::Display::Hex,display_hint:"hex",solved:false,plaintext:None,steps:vec![],ciphertext_canonical:None};
 let args=pi_args();let axes=resolve_axes(&args,&target)?;
 anyhow::ensure!(axes.variant_masks.len()==1 && axes.variant_labels()==["hex-exact"],"variant scope");
 anyhow::ensure!(axes.layer_unit()==5376,"layer scope");anyhow::ensure!(display_names(&axes.prims)==PI_PRIMS,"primitive scope");
 let plan=Plan::new(Tier::T3,&axes);let text=sweep_input_text(&target);
 let ctx=Ctx{plan:&plan,axes:&axes,text:&text,display:target.display,oracle:ra_oracle::oracle("printable-0.75").unwrap(),initial_decode:"hexdecode"};
 let mut rows=Vec::with_capacity(16128);let mut groups:std::collections::BTreeMap<Vec<u8>,Vec<String>>=std::collections::BTreeMap::new();
 for pd in 0..3 {let staged=ctx.stage(0,pd);for ix in 0..axes.layer_unit(){let mut r=ix as usize;
  let vi=r%axes.ivs.len();r/=axes.ivs.len();let di=r%axes.kds.len();r/=axes.kds.len();let ki=r%axes.keys.len();r/=axes.keys.len();let mi=r%axes.modes.len();r/=axes.modes.len();let pi=r%axes.prims.len();r/=axes.prims.len();anyhow::ensure!(r==0,"index");
  let l=LayerParams{prim:&axes.prims[pi],mode:axes.modes[mi],key:&axes.keys[ki],kd:axes.kds[di],iv:&axes.ivs[vi]};
  let rid=format!("pre={}|prim={}|mode={}|key={}|kd={}|iv={}",axes.pres[pd].label(),axes.prim_labels[pi],l.mode,l.key.label,l.kd,l.iv.0);
  let (status,out)=match &staged.canonical{None=>("decode_failed",None),Some(c)=>match l.decrypt(c){Some(v) if v.is_empty()=>("ready_empty",Some(v)),Some(v)=>("ready",Some(v)),None=>("layer_inapplicable",None)}};
  let mut row=serde_json::json!({"id":rid,"pre":axes.pres[pd].label(),"layer_index":ix,"primitive":axes.prim_labels[pi],"mode":l.mode.to_string(),"key":l.key.label,"key_hex":hex::encode(&l.key.bytes),"kd":l.kd.to_string(),"iv":l.iv.0,"status":status});
  if let Some(v)=out{let h=pi_hist(&v);let sha=hex::encode(ra_merkle::h(&v));row["length"]=serde_json::json!(v.len());row["sha256"]=serde_json::json!(sha);row["distinct_bytes"]=serde_json::json!(h.iter().filter(|&&n|n>0).count());row["histogram"]=serde_json::json!(h);row["bytes_hex"]=serde_json::json!(hex::encode(&v));groups.entry(v).or_default().push(rid);}
  rows.push(row);
 }}
 anyhow::ensure!(rows.len()==16128,"rows");let ids=rows.iter().map(|r|r["id"].as_str().unwrap()).collect::<std::collections::BTreeSet<_>>();anyhow::ensure!(ids.len()==16128,"duplicate ids");let exact=groups.into_iter().map(|(bytes,ids)|serde_json::json!({"length":bytes.len(),"sha256":hex::encode(ra_merkle::h(&bytes)),"ids":ids})).collect::<Vec<_>>();
 Ok(serde_json::json!({"identity":"ASTRA","target_evaluated":id=="rev7","boundary":"l1.decrypt output before xf/codec/layer2/oracle","scope":{"labels":16128,"variant":["hex-exact"],"pre":PI_PRES,"primitives":PI_PRIMS,"modes":PI_MODES,"keys":PI_KEYS,"kds":PI_KDS,"ivs":PI_IVS,"toolfmt":["none"]},"rows":rows,"exact_output_groups":exact}))
}
fn pi_controls(path:&Path)->Result<()>{
 let plain=(0..200).map(|i|0x80+(i%40) as u8).collect::<Vec<_>>();let iv=vec![b'0';16];
 let ct=ra_prim::encrypt("aes",Mode::Cfb8,b"Zombies",&iv,KeyDerivation::NullPadNextSupported,&plain).context("plant encrypt")?;let hx=hex::encode_upper(&ct);
 let raw_rev=hx.chars().rev().collect::<String>();let ws=hx.as_bytes().chunks(5).map(|x|std::str::from_utf8(x).unwrap()).collect::<Vec<_>>();let raw_words=ws.into_iter().rev().collect::<Vec<_>>().join(" ");
 let z=pi_inventory(hx.clone(),"synthetic")?;let a=pi_inventory(raw_rev,"synthetic")?;let b=pi_inventory(raw_words,"synthetic")?;let wanted=hex::encode(&plain);let mut paths=serde_json::Map::new();
 for (name,doc) in [("identity",&z),("reverse",&a),("reverse_words",&b)] {let n=doc["rows"].as_array().unwrap().iter().filter(|r|r["pre"]==name&&r["primitive"]=="AES"&&r["mode"]=="cfb"&&r["key"]=="Zombies"&&r["kd"]=="null-pad-next-supported"&&r["iv"]=="ascii0"&&r["bytes_hex"]==wanted).count();anyhow::ensure!(n==1,"truth {name} {n}");paths.insert(name.into(),serde_json::json!({"truth_matches":n,"labels":16128}));}
 let bad=pi_inventory("A".into(),"malformed")?;let mut status_counts=std::collections::BTreeMap::<String,u64>::new();for r in bad["rows"].as_array().unwrap(){*status_counts.entry(r["status"].as_str().unwrap().to_string()).or_default()+=1;}anyhow::ensure!(!status_counts.contains_key("ready"),"malformed produced nonempty output");anyhow::ensure!(status_counts.contains_key("ready_empty")&&status_counts.contains_key("layer_inapplicable"),"empty/inapplicable separation");
 pi_write_new(path,&serde_json::json!({"identity":"ASTRA","target_evaluated":false,"status":"synthetic controls complete","plant":{"length":plain.len(),"distinct_bytes":40,"sha256":hex::encode(ra_merkle::h(&plain)),"bytes_hex":hex::encode(&plain)},"paths":paths,"empty_decoded":{"input":"A","note":"actual RA hex normalization yields an empty canonical byte string","labels":16128,"status_counts":status_counts}}))
}
pub fn run_prefix_inventory(data:&Path,args:PrefixInventoryArgs)->Result<()> {if !args.run_target{return pi_controls(&args.output);}let t=crate::corpus::load_target(data,"rev7")?;pi_write_new(&args.output,&pi_inventory(t.raw,"rev7")?)}
