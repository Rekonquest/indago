import { useState, useRef, useCallback, useEffect } from "react";

// ─── PALETTE ────────────────────────────────────────────────────────────
const P = {
  bg:"#0c0e14",s1:"#12151e",s2:"#181c28",s3:"#1e2333",s4:"#252a3a",
  b1:"#2a3045",b2:"#353d55",b3:"#1a1f2e",
  t1:"#e2e5ec",t2:"#a0a8b8",t3:"#6b7490",t4:"#454e68",
  acc:"#5b8def",accD:"#3a5eb0",accBg:"#1a2a4a",
  grn:"#34d399",grnD:"#064e3b",grnBg:"#0d2a20",
  amb:"#fbbf24",ambD:"#78350f",ambBg:"#2a2010",
  red:"#f87171",redD:"#7f1d1d",redBg:"#2a1515",
  pur:"#a78bfa",purD:"#4c1d95",purBg:"#1a152a",
  cyn:"#22d3ee",cynBg:"#0a2530",
  wht:"#ffffff",
};
const EC={person:"#5b8def",company:"#a78bfa",domain:"#22d3ee",address:"#34d399",phone:"#fbbf24",document:"#f87171",email:"#f472b6",ip:"#fb923c"};
const SC={corroborated:{bg:P.grnBg,c:P.grn,l:"Corroborated"},asserted:{bg:P.ambBg,c:P.amb,l:"Asserted"},disputed:{bg:P.redBg,c:P.red,l:"Disputed"},retracted:{bg:P.s2,c:P.t4,l:"Retracted"}};

// ─── DATA ───────────────────────────────────────────────────────────────
const CASES=[
  {id:1,name:"Project Meridian",desc:"Shell company network — Panama/Cyprus routing",entities:47,claims:23,evidence:89,status:"active",updated:"2h ago",confidence:72,notes:3},
  {id:2,name:"Coastal Development",desc:"Zoning irregularities — County permits & land deals",entities:31,claims:14,evidence:52,status:"active",updated:"1d ago",confidence:58,notes:7},
  {id:3,name:"Signal Tower",desc:"Telecom infrastructure ownership trace — beneficial owners",entities:19,claims:8,evidence:34,status:"paused",updated:"5d ago",confidence:41,notes:2},
];
const ENTITIES=[
  {id:"e1",type:"person",name:"Marcus Webb",claims:6,connections:8,firstSeen:"2024-03-12",flag:"subject",notes:"Primary subject. Connected to at least 3 shell entities in Cyprus."},
  {id:"e2",type:"company",name:"Meridian Holdings Ltd",claims:4,connections:12,firstSeen:"2024-01-08",flag:"subject",notes:"Registered in Limassol. Dormant filing history."},
  {id:"e3",type:"company",name:"CyprusVenture LLC",claims:3,connections:5,firstSeen:"2024-02-19",flag:null,notes:"Shares registered address with Meridian Holdings."},
  {id:"e4",type:"domain",name:"meridian-group.biz",claims:2,connections:3,firstSeen:"2024-04-01",flag:null,notes:"WHOIS privacy enabled. Reverse WHOIS links to Webb email."},
  {id:"e5",type:"person",name:"Elena Kozlov",claims:3,connections:4,firstSeen:"2024-03-22",flag:null,notes:"Listed as company secretary on multiple filings."},
  {id:"e6",type:"address",name:"12 Harbour Rd, Limassol",claims:2,connections:6,firstSeen:"2024-02-25",flag:"key",notes:"Registered address for 3+ entities. Virtual office."},
  {id:"e7",type:"phone",name:"+357-25-XXX-XXX",claims:1,connections:2,firstSeen:"2024-05-10",flag:null,notes:"Appears on Webb's older LinkedIn profile."},
  {id:"e8",type:"document",name:"Corp Registry Filing #4401",claims:2,connections:3,firstSeen:"2024-01-15",flag:"key",notes:"Original incorporation document. Lists Webb as sole director."},
  {id:"e9",type:"company",name:"Coastal Dev Partners",claims:3,connections:4,firstSeen:"2024-06-01",flag:null,notes:"US-based. Webb listed as former VP of Operations."},
  {id:"e10",type:"person",name:"James Harlow",claims:2,connections:3,firstSeen:"2024-07-14",flag:null,notes:"Current director at Coastal Dev. Possible Webb associate."},
  {id:"e11",type:"email",name:"m.webb@proton.me",claims:1,connections:2,firstSeen:"2024-04-03",flag:null,notes:"Found via reverse WHOIS on meridian-group.biz"},
  {id:"e12",type:"ip",name:"185.234.XX.XX",claims:1,connections:2,firstSeen:"2024-04-05",flag:null,notes:"Shared hosting. Also hosts cyprusventure.com"},
];
const CLAIMS=[
  {id:"c1",subj:"Marcus Webb",pred:"is director of",obj:"Meridian Holdings Ltd",status:"corroborated",conf:92,sources:3,ev:["Corp registry filing","LinkedIn archive","News article"],created:"2024-03-12",author:"Corporate Registry agent"},
  {id:"c2",subj:"Meridian Holdings Ltd",pred:"registered at",obj:"12 Harbour Rd, Limassol",status:"asserted",conf:78,sources:1,ev:["Corp registry filing"],created:"2024-02-25",author:"Corporate Registry agent"},
  {id:"c3",subj:"CyprusVenture LLC",pred:"shares address with",obj:"Meridian Holdings Ltd",status:"corroborated",conf:88,sources:2,ev:["Corp registry filing","WHOIS snapshot"],created:"2024-02-26",author:"You"},
  {id:"c4",subj:"Elena Kozlov",pred:"is secretary of",obj:"CyprusVenture LLC",status:"asserted",conf:65,sources:1,ev:["Corp registry filing"],created:"2024-03-22",author:"Corporate Registry agent"},
  {id:"c5",subj:"meridian-group.biz",pred:"registered by",obj:"Marcus Webb",status:"disputed",conf:45,sources:2,ev:["WHOIS snapshot","Reverse WHOIS"],created:"2024-04-03",author:"WHOIS/DNS agent"},
  {id:"c6",subj:"Marcus Webb",pred:"previously employed at",obj:"Coastal Dev Partners",status:"asserted",conf:71,sources:1,ev:["LinkedIn archive"],created:"2024-06-01",author:"Social Profiles agent"},
  {id:"c7",subj:"185.234.XX.XX",pred:"hosts",obj:"meridian-group.biz",status:"corroborated",conf:95,sources:2,ev:["DNS lookup","IP scan"],created:"2024-04-05",author:"WHOIS/DNS agent"},
  {id:"c8",subj:"m.webb@proton.me",pred:"linked to",obj:"Marcus Webb",status:"asserted",conf:60,sources:1,ev:["Reverse WHOIS"],created:"2024-04-03",author:"WHOIS/DNS agent"},
];
const EVIDENCE=[
  {id:"ev1",type:"warc",title:"Corp Registry — Meridian Holdings",captured:"2024-03-12 14:22",hash:"a3f2c8d1...9c01e4b7",size:"2.1 MB",fmt:"WARC",linked:["c1","c2"]},
  {id:"ev2",type:"warc",title:"LinkedIn — Marcus Webb (archived)",captured:"2024-03-15 09:11",hash:"b7e14a02...3d44f891",size:"1.4 MB",fmt:"WARC",linked:["c1","c6"]},
  {id:"ev3",type:"json",title:"WHOIS — meridian-group.biz",captured:"2024-04-01 16:05",hash:"c2d8e3f7...f192a0b5",size:"12 KB",fmt:"JSON",linked:["c5"]},
  {id:"ev4",type:"png",title:"Screenshot — meridian-group.biz",captured:"2024-04-01 16:06",hash:"d9a3b1c4...e721f082",size:"890 KB",fmt:"PNG",linked:[]},
  {id:"ev5",type:"warc",title:"Herald Tribune — Webb profile",captured:"2024-05-20 11:30",hash:"e4f71d92...a083c5e6",size:"340 KB",fmt:"WARC",linked:["c1"]},
  {id:"ev6",type:"json",title:"Reverse WHOIS results",captured:"2024-04-03 08:45",hash:"f1b2a9c3...c456d7e8",size:"28 KB",fmt:"JSON",linked:["c5","c8"]},
  {id:"ev7",type:"json",title:"DNS A/MX records — meridian-group.biz",captured:"2024-04-05 10:12",hash:"a1b2c3d4...e5f6a7b8",size:"4 KB",fmt:"JSON",linked:["c7"]},
  {id:"ev8",type:"warc",title:"Corp Registry — CyprusVenture LLC",captured:"2024-02-20 13:40",hash:"c3d4e5f6...a7b8c9d0",size:"1.8 MB",fmt:"WARC",linked:["c3","c4"]},
  {id:"ev9",type:"png",title:"Screenshot — Cyprus company search",captured:"2024-02-20 13:41",hash:"d4e5f6a7...b8c9d0e1",size:"1.2 MB",fmt:"PNG",linked:["c3"]},
  {id:"ev10",type:"json",title:"IP geolocation — 185.234.XX.XX",captured:"2024-04-05 10:15",hash:"e5f6a7b8...c9d0e1f2",size:"3 KB",fmt:"JSON",linked:["c7"]},
];
const TIMELINE=[
  {date:"2024-01-08",label:"Meridian Holdings incorporated",type:"event",ent:"e2"},
  {date:"2024-01-15",label:"Registry filing captured",type:"capture",ent:"e8"},
  {date:"2024-02-19",label:"CyprusVenture LLC first appears in records",type:"event",ent:"e3"},
  {date:"2024-02-25",label:"Shared address discovered — 12 Harbour Rd",type:"discovery",ent:"e6"},
  {date:"2024-03-12",label:"Marcus Webb identified as sole director",type:"discovery",ent:"e1"},
  {date:"2024-03-15",label:"Webb LinkedIn profile archived",type:"capture",ent:"e1"},
  {date:"2024-03-22",label:"Elena Kozlov listed as secretary",type:"discovery",ent:"e5"},
  {date:"2024-04-01",label:"Domain meridian-group.biz registered",type:"event",ent:"e4"},
  {date:"2024-04-03",label:"Reverse WHOIS links domain to Webb email",type:"discovery",ent:"e11"},
  {date:"2024-04-05",label:"Shared IP hosting discovered",type:"discovery",ent:"e12"},
  {date:"2024-05-10",label:"Phone number linked to Webb via old profile",type:"discovery",ent:"e7"},
  {date:"2024-05-20",label:"Herald Tribune article mentions Webb",type:"event",ent:"e1"},
  {date:"2024-06-01",label:"Coastal Dev Partners connection surfaces",type:"discovery",ent:"e9"},
  {date:"2024-07-14",label:"James Harlow identified at Coastal Dev",type:"discovery",ent:"e10"},
];
const AGENTS=[
  {name:"Domain Intel",status:"idle",type:"tool",last:"2h ago",findings:4,desc:"DNS, cert transparency, subdomain enum"},
  {name:"Corporate Registry",status:"running",type:"tool",last:"now",findings:12,desc:"Company filings, directors, shareholders"},
  {name:"Social Profiles",status:"idle",type:"tool",last:"1d ago",findings:7,desc:"Username enum, profile archiving"},
  {name:"WHOIS / DNS",status:"idle",type:"tool",last:"3h ago",findings:9,desc:"Domain registration, reverse lookups, IP resolution"},
  {name:"Web Archiver",status:"queued",type:"tool",last:"6h ago",findings:15,desc:"Page capture, WARC freeze, screenshot"},
  {name:"Email Intel",status:"idle",type:"tool",last:"2d ago",findings:3,desc:"Breach check, email-to-name, provider ID"},
  {name:"Corporate Structure",status:"idle",type:"mode",last:"1d ago",findings:null,desc:"Maps ownership trees, shared directors, shell patterns"},
  {name:"Person of Interest",status:"active",type:"mode",last:"2h ago",findings:null,desc:"Builds full profile — employment, addresses, associates"},
  {name:"Financial Flow",status:"idle",type:"mode",last:"3d ago",findings:null,desc:"Traces money movement, shared accounts, payment patterns"},
];
const ACTIVITY=[
  {time:"14:22",text:"Corporate Registry agent returned 3 new entities from Cyprus Dept of Registrar",type:"agent"},
  {time:"14:20",text:"You approved live collection: Cyprus Dept of Registrar query",type:"user"},
  {time:"13:45",text:"Claim c7 auto-promoted to Corroborated (2 independent sources)",type:"system"},
  {time:"13:30",text:"Web Archiver captured meridian-group.biz/about — WARC frozen",type:"agent"},
  {time:"12:15",text:"Person of Interest mode proposed: query Companies House UK for Webb",type:"agent"},
  {time:"11:50",text:"You added note to Marcus Webb entity",type:"user"},
  {time:"11:02",text:"WHOIS/DNS agent completed scan — 2 new claims proposed",type:"agent"},
  {time:"09:30",text:"Session started",type:"system"},
];
const APPROVALS=[
  {id:"a1",agent:"Person of Interest",target:"Companies House UK",reason:"Webb may have UK directorships",risk:"Live external query — will contact gov registry",proposed:"12:15"},
  {id:"a2",agent:"Social Profiles",target:"Twitter/X API",reason:"Username 'mwebb_consulting' found in breach data",risk:"Live external query — rate-limited API",proposed:"14:25"},
];

// ─── GRAPH NODE POSITIONS ───────────────────────────────────────────────
const INIT_NODES=[
  {id:"e1",x:400,y:160},{id:"e2",x:220,y:260},{id:"e3",x:540,y:310},{id:"e4",x:160,y:100},
  {id:"e5",x:640,y:200},{id:"e6",x:380,y:380},{id:"e7",x:540,y:80},{id:"e8",x:80,y:320},
  {id:"e9",x:700,y:380},{id:"e10",x:760,y:280},{id:"e11",x:280,y:60},{id:"e12",x:440,y:440},
];
const EDGES=[
  {f:"e1",t:"e2",l:"director of"},{f:"e2",t:"e6",l:"registered at"},{f:"e3",t:"e6",l:"shares address"},
  {f:"e5",t:"e3",l:"secretary of"},{f:"e4",t:"e1",l:"registered by"},{f:"e7",t:"e1",l:"linked to"},
  {f:"e8",t:"e2",l:"documents"},{f:"e1",t:"e9",l:"prev. employed"},{f:"e10",t:"e9",l:"director"},
  {f:"e2",t:"e3",l:"related entity"},{f:"e11",t:"e1",l:"email of"},{f:"e12",t:"e4",l:"hosts"},
  {f:"e11",t:"e4",l:"WHOIS registrant"},{f:"e12",t:"e3",l:"also hosts"},
];

// ─── ICONS (minimal) ────────────────────────────────────────────────────
const I={
  person:<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="8" r="4"/><path d="M4 21v-1a6 6 0 0112 0v1"/></svg>,
  company:<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18M15 3v18M3 9h18M3 15h18"/></svg>,
  domain:<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/></svg>,
  address:<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7z"/></svg>,
  phone:<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 16.92v3a2 2 0 01-2.18 2A19.79 19.79 0 012.12 4.18 2 2 0 014.11 2h3"/></svg>,
  document:<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/></svg>,
  email:<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M22 4L12 13 2 4"/></svg>,
  ip:<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/></svg>,
};

// ─── SMALL COMPONENTS ───────────────────────────────────────────────────
const Badge=({status})=>{const s=SC[status];return <span style={{background:s.bg,color:s.c,padding:"2px 7px",borderRadius:3,fontSize:10,fontWeight:600,letterSpacing:".04em",textTransform:"uppercase"}}>{s.l}</span>};
const TypeTag=({type})=><span style={{background:(EC[type]||P.t4)+"15",color:EC[type]||P.t4,padding:"2px 6px",borderRadius:3,fontSize:10,fontWeight:500,display:"inline-flex",alignItems:"center",gap:3,textTransform:"capitalize"}}>{I[type]||I.document}{type}</span>;
const Conf=({v,w})=>{const c=v>=80?P.grn:v>=50?P.amb:P.red;return <div style={{display:"flex",alignItems:"center",gap:4,width:w||"100%"}}><div style={{flex:1,height:4,background:P.b1,borderRadius:2,overflow:"hidden"}}><div style={{width:`${v}%`,height:"100%",background:c,borderRadius:2}}/></div><span style={{fontSize:10,color:c,fontWeight:600,minWidth:24}}>{v}%</span></div>};
const Dot=({c,pulse})=><span style={{width:7,height:7,borderRadius:"50%",background:c,display:"inline-block",boxShadow:pulse?`0 0 6px ${c}`:"none"}}/>;
const Btn=({children,primary,small,onClick,style:sx})=><button onClick={onClick} style={{background:primary?P.acc:"transparent",color:primary?"#fff":P.t2,border:primary?"none":`1px solid ${P.b1}`,borderRadius:6,padding:small?"4px 8px":"6px 14px",fontSize:small?11:12,fontWeight:500,cursor:"pointer",display:"inline-flex",alignItems:"center",gap:4,...sx}}>{children}</button>;
const Tab=({active,children,onClick})=><button onClick={onClick} style={{background:active?P.accBg:"transparent",color:active?P.acc:P.t3,border:"none",borderBottom:`2px solid ${active?P.acc:"transparent"}`,padding:"6px 12px",fontSize:12,fontWeight:500,cursor:"pointer"}}>{children}</button>;

// ─── SIDEBAR ────────────────────────────────────────────────────────────
const NAV=[
  {id:"home",icon:"⌂",tip:"Cases"},
  {id:"_sep"},
  {id:"graph",icon:"◉",tip:"Graph"},
  {id:"timeline",icon:"━",tip:"Timeline"},
  {id:"claims",icon:"✓",tip:"Claims"},
  {id:"vault",icon:"⊟",tip:"Evidence"},
  {id:"entities",icon:"≡",tip:"Entities"},
  {id:"agents",icon:"◈",tip:"Agents"},
  {id:"_sep2"},
  {id:"activity",icon:"◷",tip:"Activity"},
  {id:"notes",icon:"✎",tip:"Notes"},
];

function Sidebar({view,onNav,hasCase}){
  return <div style={{width:48,background:P.s1,borderRight:`1px solid ${P.b1}`,display:"flex",flexDirection:"column",alignItems:"center",paddingTop:8,gap:1,flexShrink:0}}>
    {NAV.filter(n=>n.id==="home"||n.id.startsWith("_sep")||hasCase).map((n,i)=>{
      if(n.id.startsWith("_sep")) return <div key={i} style={{width:20,height:1,background:P.b1,margin:"4px 0"}}/>;
      return <button key={n.id} onClick={()=>onNav(n.id)} title={n.tip} style={{
        width:36,height:36,display:"flex",alignItems:"center",justifyContent:"center",fontSize:16,
        background:view===n.id?P.accBg:"transparent",color:view===n.id?P.acc:P.t4,
        border:"none",borderRadius:7,cursor:"pointer",transition:"all .1s",fontFamily:"inherit",
      }}>{n.icon}</button>;
    })}
  </div>;
}

// ─── CASE DASHBOARD ─────────────────────────────────────────────────────
function CaseDash({onOpen}){
  return <div style={{flex:1,padding:28,overflow:"auto"}}>
    <div style={{maxWidth:860,margin:"0 auto"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:24}}>
        <div><h1 style={{fontSize:20,fontWeight:600,color:P.t1,margin:0}}>Investigations</h1>
        <p style={{fontSize:12,color:P.t3,margin:"4px 0 0"}}>{CASES.length} cases · {CASES.filter(c=>c.status==="active").length} active</p></div>
        <Btn primary>＋ New Investigation</Btn>
      </div>
      <div style={{display:"flex",flexDirection:"column",gap:10}}>
        {CASES.map(c=><button key={c.id} onClick={()=>onOpen(c)} style={{
          background:P.s1,border:`1px solid ${P.b1}`,borderRadius:10,padding:18,cursor:"pointer",textAlign:"left",width:"100%",transition:"all .15s"
        }} onMouseOver={e=>{e.currentTarget.style.borderColor=P.acc+"50";e.currentTarget.style.background=P.s2}}
           onMouseOut={e=>{e.currentTarget.style.borderColor=P.b1;e.currentTarget.style.background=P.s1}}>
          <div style={{display:"flex",justifyContent:"space-between",marginBottom:10}}>
            <div><div style={{fontSize:15,fontWeight:600,color:P.t1}}>{c.name}</div>
            <div style={{fontSize:12,color:P.t3,marginTop:2}}>{c.desc}</div></div>
            <div style={{display:"flex",alignItems:"center",gap:6}}><Dot c={c.status==="active"?P.grn:P.amb} pulse={c.status==="active"}/><span style={{fontSize:11,color:P.t3}}>{c.updated}</span></div>
          </div>
          <div style={{display:"flex",gap:20,marginBottom:10}}>
            {[["Entities",c.entities],["Claims",c.claims],["Evidence",c.evidence],["Notes",c.notes]].map(([l,v])=>
              <div key={l}><div style={{fontSize:17,fontWeight:700,color:P.t1}}>{v}</div><div style={{fontSize:10,color:P.t3,textTransform:"uppercase",letterSpacing:".05em"}}>{l}</div></div>
            )}
          </div>
          <Conf v={c.confidence} w={160}/>
        </button>)}
      </div>
    </div>
  </div>;
}

// ─── INTERACTIVE GRAPH ──────────────────────────────────────────────────
function Graph({sel,onSel,onDblClick,typeFilter}){
  const [nodes,setNodes]=useState(INIT_NODES.map(n=>({...n})));
  const [drag,setDrag]=useState(null);
  const [pan,setPan]=useState({x:0,y:0});
  const [zoom,setZoom]=useState(1);
  const svgRef=useRef(null);
  const [hoverNode,setHoverNode]=useState(null);
  const [hoverEdge,setHoverEdge]=useState(null);

  const getNode=id=>nodes.find(n=>n.id===id);
  const getEnt=id=>ENTITIES.find(e=>e.id===id);

  const handleMouseDown=(e,id)=>{e.stopPropagation();const svg=svgRef.current.getBoundingClientRect();setDrag({id,offX:e.clientX-svg.left,offY:e.clientY-svg.top,nodeX:getNode(id).x,nodeY:getNode(id).y,startX:e.clientX,startY:e.clientY})};
  const handleMouseMove=useCallback((e)=>{if(!drag)return;const dx=(e.clientX-drag.startX)/zoom;const dy=(e.clientY-drag.startY)/zoom;setNodes(prev=>prev.map(n=>n.id===drag.id?{...n,x:drag.nodeX+dx,y:drag.nodeY+dy}:n))},[drag,zoom]);
  const handleMouseUp=useCallback(()=>{if(drag){const n=getNode(drag.id);const moved=Math.abs(n.x-drag.nodeX)>3||Math.abs(n.y-drag.nodeY)>3;if(!moved)onSel(drag.id);setDrag(null)}},[drag,onSel]);
  useEffect(()=>{if(drag){window.addEventListener("mousemove",handleMouseMove);window.addEventListener("mouseup",handleMouseUp);return()=>{window.removeEventListener("mousemove",handleMouseMove);window.removeEventListener("mouseup",handleMouseUp)}}},[drag,handleMouseMove,handleMouseUp]);

  const filteredNodes=typeFilter==="all"?nodes:nodes.filter(n=>{const ent=getEnt(n.id);return ent&&ent.type===typeFilter});
  const filteredIds=new Set(filteredNodes.map(n=>n.id));
  const filteredEdges=EDGES.filter(e=>filteredIds.has(e.f)&&filteredIds.has(e.t));

  return <div style={{flex:1,position:"relative",overflow:"hidden",background:P.bg}}>
    {/* Controls */}
    <div style={{position:"absolute",top:8,left:8,display:"flex",gap:4,zIndex:3}}>
      <Btn small onClick={()=>setZoom(z=>Math.min(z+.15,2.5))} style={{width:28,height:28,padding:0,justifyContent:"center"}}>＋</Btn>
      <Btn small onClick={()=>setZoom(z=>Math.max(z-.15,.3))} style={{width:28,height:28,padding:0,justifyContent:"center"}}>−</Btn>
      <Btn small onClick={()=>{setZoom(1);setNodes(INIT_NODES.map(n=>({...n})))}} style={{fontSize:10}}>Reset</Btn>
    </div>
    {/* Hover tooltip */}
    {hoverNode&&!drag&&<div style={{position:"absolute",top:8,right:8,background:P.s2,border:`1px solid ${P.b1}`,borderRadius:8,padding:10,zIndex:3,minWidth:180,pointerEvents:"none"}}>
      {(()=>{const ent=getEnt(hoverNode);if(!ent)return null;const rc=CLAIMS.filter(c=>c.subj===ent.name||c.obj===ent.name);return<>
        <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:6}}><TypeTag type={ent.type}/>{ent.flag&&<span style={{fontSize:9,background:ent.flag==="subject"?P.redBg:P.ambBg,color:ent.flag==="subject"?P.red:P.amb,padding:"1px 5px",borderRadius:3,textTransform:"uppercase",fontWeight:700}}>{ent.flag}</span>}</div>
        <div style={{fontSize:13,fontWeight:600,color:P.t1,marginBottom:4}}>{ent.name}</div>
        <div style={{fontSize:11,color:P.t3,marginBottom:6}}>{ent.notes}</div>
        <div style={{display:"flex",gap:12,fontSize:11,color:P.t3}}>
          <span>{ent.claims} claims</span><span>{ent.connections} links</span>
        </div>
        {rc.length>0&&<div style={{marginTop:8,borderTop:`1px solid ${P.b1}`,paddingTop:6}}>
          {rc.slice(0,3).map(c=><div key={c.id} style={{fontSize:10,color:P.t3,marginBottom:3,display:"flex",alignItems:"center",gap:4}}>
            <Badge status={c.status}/><span style={{color:P.t2}}>{c.pred} {c.obj===ent.name?c.subj:c.obj}</span>
          </div>)}
        </div>}
      </>})()}
    </div>}

    <svg ref={svgRef} width="100%" height="100%" style={{cursor:drag?"grabbing":"default"}}
      onWheel={e=>{e.preventDefault();setZoom(z=>Math.max(.3,Math.min(2.5,z-(e.deltaY*.001))))}}>
      <defs>
        <marker id="ah" markerWidth="7" markerHeight="5" refX="7" refY="2.5" orient="auto"><polygon points="0 0,7 2.5,0 5" fill={P.t4}/></marker>
        <marker id="ahH" markerWidth="7" markerHeight="5" refX="7" refY="2.5" orient="auto"><polygon points="0 0,7 2.5,0 5" fill={P.acc}/></marker>
      </defs>
      <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
        {/* Edges */}
        {filteredEdges.map((edge,i)=>{
          const f=getNode(edge.f),t=getNode(edge.t);if(!f||!t)return null;
          const mx=(f.x+t.x)/2,my=(f.y+t.y)/2;
          const isHover=hoverEdge===i||hoverNode===edge.f||hoverNode===edge.t;
          const isSel=sel===edge.f||sel===edge.t;
          return <g key={i} onMouseEnter={()=>setHoverEdge(i)} onMouseLeave={()=>setHoverEdge(null)}>
            <line x1={f.x} y1={f.y} x2={t.x} y2={t.y} stroke={isHover||isSel?P.acc+"90":P.t4+"40"} strokeWidth={isHover||isSel?1.5:1} markerEnd={isHover?"url(#ahH)":"url(#ah)"} strokeDasharray={isHover?"none":"4,3"}/>
            <text x={mx} y={my-5} fill={isHover||isSel?P.t2:P.t4} fontSize={9} textAnchor="middle" fontFamily="inherit" style={{pointerEvents:"none"}}>{edge.l}</text>
          </g>;
        })}
        {/* Nodes */}
        {filteredNodes.map(node=>{
          const ent=getEnt(node.id);if(!ent)return null;
          const color=EC[ent.type]||P.t4;
          const isSel=sel===node.id;const isHov=hoverNode===node.id;
          const r=isSel?24:isHov?21:18;
          return <g key={node.id} style={{cursor:"pointer"}} onMouseDown={e=>handleMouseDown(e,node.id)}
            onMouseEnter={()=>setHoverNode(node.id)} onMouseLeave={()=>setHoverNode(null)}
            onDoubleClick={()=>onDblClick&&onDblClick(node.id)}>
            {isSel&&<circle cx={node.x} cy={node.y} r={r+8} fill={color+"08"} stroke={color+"20"} strokeWidth={1}/>}
            <circle cx={node.x} cy={node.y} r={r} fill={color+"15"} stroke={isSel?color:isHov?color+"a0":color+"40"} strokeWidth={isSel?2.5:isHov?2:1.2}/>
            <circle cx={node.x} cy={node.y} r={5} fill={color}/>
            {ent.flag&&<><circle cx={node.x+13} cy={node.y-13} r={6} fill={P.bg}/><circle cx={node.x+13} cy={node.y-13} r={4.5} fill={ent.flag==="subject"?P.red:P.amb}/></>}
            <text x={node.x} y={node.y+r+14} fill={isSel?P.t1:isHov?P.t1:P.t2} fontSize={10} textAnchor="middle" fontWeight={isSel?600:400} fontFamily="inherit" style={{pointerEvents:"none"}}>
              {ent.name.length>22?ent.name.slice(0,20)+"…":ent.name}
            </text>
          </g>;
        })}
      </g>
    </svg>
  </div>;
}

// ─── TIMELINE (horizontal) ──────────────────────────────────────────────
const TC={event:P.acc,capture:P.grn,discovery:P.amb};
function Timeline({onSel}){
  const ref=useRef(null);
  return <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
    <div style={{padding:"12px 16px 8px",display:"flex",justifyContent:"space-between",alignItems:"center",flexShrink:0}}>
      <div style={{fontSize:14,fontWeight:600,color:P.t1}}>Timeline</div>
      <div style={{display:"flex",gap:10}}>{Object.entries(TC).map(([t,c])=><span key={t} style={{display:"flex",alignItems:"center",gap:4,fontSize:10,color:P.t3}}><Dot c={c}/>{t}</span>)}</div>
    </div>
    {/* Horizontal scrollable timeline */}
    <div ref={ref} style={{flex:1,overflowX:"auto",overflowY:"hidden",padding:"0 16px 16px"}}>
      <div style={{display:"flex",alignItems:"flex-start",minWidth:TIMELINE.length*140,height:"100%",position:"relative",paddingTop:40}}>
        {/* Axis line */}
        <div style={{position:"absolute",top:52,left:0,right:0,height:2,background:P.b1}}/>
        {TIMELINE.map((ev,i)=>{
          const ent=ENTITIES.find(e=>e.id===ev.ent);
          const above=i%2===0;
          return <div key={i} style={{width:140,flexShrink:0,position:"relative",display:"flex",flexDirection:"column",alignItems:"center"}}>
            {/* Dot on axis */}
            <div style={{position:"absolute",top:46,width:14,height:14,borderRadius:7,background:TC[ev.type],border:`3px solid ${P.bg}`,zIndex:1,boxShadow:`0 0 8px ${TC[ev.type]}30`}}/>
            {/* Connector line */}
            <div style={{position:"absolute",top:above?60:8,width:1,height:above?50:38,background:P.b1}}/>
            {/* Card */}
            <div onClick={()=>onSel(ev.ent)} style={{
              position:"absolute",top:above?110:undefined,bottom:above?undefined:0,
              background:P.s1,border:`1px solid ${P.b1}`,borderRadius:6,padding:"8px 10px",width:120,cursor:"pointer",
              transition:"border-color .1s",
            }} onMouseOver={e=>e.currentTarget.style.borderColor=P.acc+"60"} onMouseOut={e=>e.currentTarget.style.borderColor=P.b1}>
              <div style={{fontSize:10,color:TC[ev.type],fontWeight:600,marginBottom:2}}>{ev.date}</div>
              <div style={{fontSize:11,color:P.t1,lineHeight:1.3,marginBottom:4}}>{ev.label}</div>
              {ent&&<TypeTag type={ent.type}/>}
            </div>
          </div>;
        })}
      </div>
    </div>
  </div>;
}

// ─── CLAIMS ─────────────────────────────────────────────────────────────
function ClaimsView({onSel}){
  const [filter,setFilter]=useState("all");
  const [showCreate,setShowCreate]=useState(false);
  const filtered=filter==="all"?CLAIMS:CLAIMS.filter(c=>c.status===filter);
  return <div style={{flex:1,padding:16,overflow:"auto"}}>
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14}}>
      <div style={{display:"flex",alignItems:"center",gap:12}}>
        <span style={{fontSize:14,fontWeight:600,color:P.t1}}>Claims ({filtered.length})</span>
        <div style={{display:"flex",gap:3}}>{["all","corroborated","asserted","disputed"].map(f=>
          <button key={f} onClick={()=>setFilter(f)} style={{background:filter===f?P.accBg:"transparent",color:filter===f?P.acc:P.t4,border:`1px solid ${filter===f?P.acc+"40":P.b1}`,borderRadius:4,padding:"3px 8px",fontSize:10,cursor:"pointer",textTransform:"capitalize"}}>{f}</button>
        )}</div>
      </div>
      <Btn small primary onClick={()=>setShowCreate(!showCreate)}>＋ New Claim</Btn>
    </div>
    {showCreate&&<div style={{background:P.s2,border:`1px solid ${P.acc}30`,borderRadius:8,padding:14,marginBottom:12}}>
      <div style={{fontSize:12,fontWeight:600,color:P.t1,marginBottom:10}}>Create Claim</div>
      <div style={{display:"flex",gap:6,marginBottom:8}}>
        <input placeholder="Subject entity" style={{flex:1,background:P.s3,border:`1px solid ${P.b1}`,borderRadius:4,padding:"6px 8px",color:P.t1,fontSize:12,outline:"none"}}/>
        <select style={{background:P.s3,border:`1px solid ${P.b1}`,borderRadius:4,padding:"6px 8px",color:P.t2,fontSize:12}}>
          <option>is director of</option><option>registered at</option><option>shares address with</option><option>is secretary of</option><option>registered by</option><option>previously employed at</option><option>linked to</option><option>hosts</option>
        </select>
        <input placeholder="Object entity" style={{flex:1,background:P.s3,border:`1px solid ${P.b1}`,borderRadius:4,padding:"6px 8px",color:P.t1,fontSize:12,outline:"none"}}/>
      </div>
      <div style={{display:"flex",gap:6,alignItems:"center"}}>
        <input placeholder="Link evidence items..." style={{flex:1,background:P.s3,border:`1px solid ${P.b1}`,borderRadius:4,padding:"6px 8px",color:P.t1,fontSize:12,outline:"none"}}/>
        <Btn small primary>Create</Btn>
        <Btn small onClick={()=>setShowCreate(false)}>Cancel</Btn>
      </div>
    </div>}
    <div style={{display:"flex",flexDirection:"column",gap:6}}>
      {filtered.map(c=><div key={c.id} style={{background:P.s1,border:`1px solid ${P.b1}`,borderRadius:8,padding:12}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:8}}>
          <div style={{fontSize:13,color:P.t1,lineHeight:1.5}}>
            <span style={{color:P.acc,fontWeight:600,cursor:"pointer"}} onClick={()=>{const e=ENTITIES.find(x=>x.name===c.subj);if(e)onSel(e.id)}}>{c.subj}</span>
            <span style={{color:P.t3,padding:"0 5px"}}>{c.pred}</span>
            <span style={{color:P.pur,fontWeight:600,cursor:"pointer"}} onClick={()=>{const e=ENTITIES.find(x=>x.name===c.obj);if(e)onSel(e.id)}}>{c.obj}</span>
          </div>
          <Badge status={c.status}/>
        </div>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
          <div style={{display:"flex",gap:12,fontSize:11,color:P.t3}}>
            <span>{c.sources} source{c.sources>1?"s":""}</span>
            <span>{c.ev.length} evidence</span>
            <span>by {c.author}</span>
            <span style={{fontFamily:"monospace"}}>{c.created}</span>
          </div>
          <Conf v={c.conf} w={100}/>
        </div>
        <div style={{display:"flex",gap:4,flexWrap:"wrap"}}>
          {c.ev.map((e,i)=><span key={i} style={{background:P.s3,color:P.t3,padding:"2px 6px",borderRadius:3,fontSize:9,display:"flex",alignItems:"center",gap:3}}>🔗 {e}</span>)}
        </div>
      </div>)}
    </div>
  </div>;
}

// ─── EVIDENCE VAULT ─────────────────────────────────────────────────────
function Vault(){
  const [selEv,setSelEv]=useState(null);
  const icons={warc:"🌐",json:"📋",png:"📸",pdf:"📄"};
  const ev=selEv?EVIDENCE.find(e=>e.id===selEv):null;
  return <div style={{flex:1,display:"flex",overflow:"hidden"}}>
    <div style={{flex:1,padding:16,overflow:"auto"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14}}>
        <span style={{fontSize:14,fontWeight:600,color:P.t1}}>Evidence Vault ({EVIDENCE.length})</span>
        <span style={{fontSize:11,color:P.t3}}>Content-addressed · tamper-evident · append-only</span>
      </div>
      {EVIDENCE.map(e=><div key={e.id} onClick={()=>setSelEv(e.id===selEv?null:e.id)} style={{
        background:selEv===e.id?P.accBg:P.s1,border:`1px solid ${selEv===e.id?P.acc+"40":P.b1}`,borderRadius:6,padding:"10px 12px",marginBottom:4,display:"flex",alignItems:"center",gap:12,cursor:"pointer",transition:"all .1s"
      }}>
        <span style={{fontSize:18}}>{icons[e.fmt.toLowerCase()]||"📎"}</span>
        <div style={{flex:1}}>
          <div style={{fontSize:12,color:P.t1,fontWeight:500}}>{e.title}</div>
          <div style={{fontSize:10,color:P.t3,marginTop:2}}>{e.captured} UTC</div>
        </div>
        <div style={{textAlign:"right"}}>
          <div style={{fontFamily:"monospace",fontSize:10,color:P.t4}}>{e.hash}</div>
          <div style={{fontSize:10,color:P.t3}}>{e.size} · {e.fmt}</div>
        </div>
      </div>)}
    </div>
    {ev&&<div style={{width:280,borderLeft:`1px solid ${P.b1}`,background:P.s1,padding:14,overflow:"auto",flexShrink:0}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
        <span style={{fontSize:13,fontWeight:600,color:P.t1}}>Evidence Detail</span>
        <button onClick={()=>setSelEv(null)} style={{background:"transparent",border:"none",color:P.t3,cursor:"pointer",fontSize:16}}>×</button>
      </div>
      <div style={{fontSize:18,textAlign:"center",padding:20,background:P.s3,borderRadius:8,marginBottom:12}}>{icons[ev.fmt.toLowerCase()]||"📎"}</div>
      {[["Title",ev.title],["Format",ev.fmt],["Size",ev.size],["Captured",ev.captured+" UTC"],["Hash",ev.hash]].map(([l,v])=>
        <div key={l} style={{marginBottom:8}}><div style={{fontSize:10,color:P.t4,textTransform:"uppercase",letterSpacing:".05em"}}>{l}</div><div style={{fontSize:12,color:l==="Hash"?P.t3:P.t1,fontFamily:l==="Hash"?"monospace":"inherit",wordBreak:"break-all"}}>{v}</div></div>
      )}
      <div style={{marginTop:12,borderTop:`1px solid ${P.b1}`,paddingTop:10}}>
        <div style={{fontSize:11,fontWeight:600,color:P.t2,marginBottom:6}}>Linked Claims ({ev.linked.length})</div>
        {ev.linked.map(cid=>{const cl=CLAIMS.find(c=>c.id===cid);return cl?<div key={cid} style={{fontSize:11,color:P.t3,marginBottom:4,display:"flex",alignItems:"center",gap:4}}>
          <Badge status={cl.status}/><span>{cl.subj} {cl.pred} {cl.obj}</span>
        </div>:null})}
        {ev.linked.length===0&&<div style={{fontSize:11,color:P.t4}}>Not linked to any claims yet</div>}
      </div>
      <div style={{marginTop:12,display:"flex",gap:6}}>
        <Btn small style={{flex:1}}>View Raw</Btn>
        <Btn small style={{flex:1}}>Export</Btn>
      </div>
    </div>}
  </div>;
}

// ─── ENTITIES TABLE ─────────────────────────────────────────────────────
function EntTable({onSel,sel}){
  const [typeF,setTypeF]=useState("all");
  const [search,setSearch]=useState("");
  const types=["all",...new Set(ENTITIES.map(e=>e.type))];
  const filtered=ENTITIES.filter(e=>(typeF==="all"||e.type===typeF)&&(search===""||e.name.toLowerCase().includes(search.toLowerCase())));
  return <div style={{flex:1,padding:16,overflow:"auto"}}>
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
      <span style={{fontSize:14,fontWeight:600,color:P.t1}}>Entities ({filtered.length})</span>
      <div style={{display:"flex",gap:6}}>
        <div style={{background:P.s2,border:`1px solid ${P.b1}`,borderRadius:4,padding:"4px 8px",display:"flex",alignItems:"center",gap:4}}>
          <span style={{color:P.t4,fontSize:12}}>⌕</span>
          <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Filter..." style={{background:"transparent",border:"none",color:P.t1,fontSize:11,outline:"none",width:100}}/>
        </div>
        <div style={{display:"flex",gap:2}}>{types.map(t=>
          <button key={t} onClick={()=>setTypeF(t)} style={{background:typeF===t?P.accBg:"transparent",color:typeF===t?P.acc:P.t4,border:`1px solid ${typeF===t?P.acc+"40":"transparent"}`,borderRadius:4,padding:"3px 6px",fontSize:10,cursor:"pointer",textTransform:"capitalize"}}>{t}</button>
        )}</div>
      </div>
    </div>
    <div style={{background:P.s1,border:`1px solid ${P.b1}`,borderRadius:8,overflow:"hidden"}}>
      <div style={{display:"grid",gridTemplateColumns:"1fr 90px 50px 50px 80px 60px",padding:"6px 12px",borderBottom:`1px solid ${P.b1}`,fontSize:10,color:P.t4,textTransform:"uppercase",letterSpacing:".05em"}}>
        <span>Name</span><span>Type</span><span>Claims</span><span>Links</span><span>First Seen</span><span></span>
      </div>
      {filtered.map(ent=><div key={ent.id} onClick={()=>onSel(ent.id)} style={{
        display:"grid",gridTemplateColumns:"1fr 90px 50px 50px 80px 60px",padding:"8px 12px",
        borderBottom:`1px solid ${P.b3}`,cursor:"pointer",alignItems:"center",
        background:sel===ent.id?P.accBg:"transparent",transition:"background .1s",
      }} onMouseOver={e=>{if(sel!==ent.id)e.currentTarget.style.background=P.s2}}
         onMouseOut={e=>{if(sel!==ent.id)e.currentTarget.style.background="transparent"}}>
        <div style={{display:"flex",alignItems:"center",gap:6}}>
          <span style={{fontSize:12,color:P.t1,fontWeight:500}}>{ent.name}</span>
          {ent.flag&&<span style={{fontSize:8,background:ent.flag==="subject"?P.redBg:P.ambBg,color:ent.flag==="subject"?P.red:P.amb,padding:"1px 4px",borderRadius:2,textTransform:"uppercase",fontWeight:700}}>{ent.flag}</span>}
        </div>
        <TypeTag type={ent.type}/>
        <span style={{fontSize:12,color:P.t2}}>{ent.claims}</span>
        <span style={{fontSize:12,color:P.t2}}>{ent.connections}</span>
        <span style={{fontSize:10,color:P.t3,fontFamily:"monospace"}}>{ent.firstSeen}</span>
        <span style={{fontSize:10,color:P.t4}}>→</span>
      </div>)}
    </div>
  </div>;
}

// ─── AGENTS ─────────────────────────────────────────────────────────────
function AgentsView(){
  const sDot={running:P.grn,active:P.acc,idle:P.t4,queued:P.amb};
  const modes=AGENTS.filter(a=>a.type==="mode"),tools=AGENTS.filter(a=>a.type==="tool");
  const Section=({title,desc,items})=><>
    <div style={{fontSize:13,fontWeight:600,color:P.t1,marginBottom:2}}>{title}</div>
    <div style={{fontSize:11,color:P.t3,marginBottom:10}}>{desc}</div>
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,marginBottom:20}}>
      {items.map(a=><div key={a.name} style={{background:P.s1,border:`1px solid ${P.b1}`,borderRadius:8,padding:10}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
          <span style={{fontSize:12,color:P.t1,fontWeight:500}}>{a.name}</span>
          <div style={{display:"flex",alignItems:"center",gap:4}}><Dot c={sDot[a.status]} pulse={a.status==="running"}/><span style={{fontSize:10,color:P.t3,textTransform:"capitalize"}}>{a.status}</span></div>
        </div>
        <div style={{fontSize:10,color:P.t3,marginBottom:6}}>{a.desc}</div>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <span style={{fontSize:10,color:P.t4}}>Last: {a.last}</span>
          {a.findings!==null&&<span style={{fontSize:10,color:P.t3}}>{a.findings} findings</span>}
          {a.type==="tool"&&<Btn small style={{padding:"2px 8px",fontSize:10}}>▸ Run</Btn>}
        </div>
      </div>)}
    </div>
  </>;
  return <div style={{flex:1,padding:16,overflow:"auto"}}>
    <Section title="Mode Agents" desc="Investigation strategies — plan sequences, coordinate tool agents, propose hypotheses" items={modes}/>
    <Section title="Tool Agents" desc="Specialized collectors — each wraps one OSINT capability and proposes candidate claims" items={tools}/>
    <div style={{background:P.s1,border:`1px solid ${P.b1}`,borderRadius:8,padding:14}}>
      <div style={{fontSize:13,fontWeight:600,color:P.t1,marginBottom:2}}>Pending Approvals ({APPROVALS.length})</div>
      <div style={{fontSize:11,color:P.t3,marginBottom:10}}>Live collection actions requiring sign-off before execution</div>
      {APPROVALS.map(a=><div key={a.id} style={{background:P.ambBg,border:`1px solid ${P.amb}25`,borderRadius:6,padding:10,marginBottom:6}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
          <div style={{flex:1}}>
            <div style={{fontSize:12,color:P.t1}}><strong>{a.agent}</strong> wants to query <strong>{a.target}</strong></div>
            <div style={{fontSize:11,color:P.t3,marginTop:2}}>{a.reason}</div>
            <div style={{fontSize:10,color:P.amb,marginTop:2}}>⚠ {a.risk}</div>
          </div>
          <div style={{display:"flex",gap:4,marginLeft:10}}>
            <Btn small primary style={{background:P.grn,color:"#000",fontWeight:600}}>Approve</Btn>
            <Btn small>Deny</Btn>
          </div>
        </div>
      </div>)}
    </div>
  </div>;
}

// ─── ACTIVITY FEED ──────────────────────────────────────────────────────
function ActivityView(){
  const typeC={agent:P.acc,user:P.grn,system:P.t3};
  return <div style={{flex:1,padding:16,overflow:"auto"}}>
    <div style={{fontSize:14,fontWeight:600,color:P.t1,marginBottom:14}}>Activity Log</div>
    {ACTIVITY.map((a,i)=><div key={i} style={{display:"flex",gap:10,marginBottom:8,padding:"8px 10px",background:P.s1,borderRadius:6,border:`1px solid ${P.b1}`}}>
      <div style={{display:"flex",flexDirection:"column",alignItems:"center",flexShrink:0,width:40}}>
        <span style={{fontSize:11,fontWeight:600,color:typeC[a.type],fontFamily:"monospace"}}>{a.time}</span>
        <Dot c={typeC[a.type]}/>
      </div>
      <div style={{fontSize:12,color:P.t2,lineHeight:1.4}}>{a.text}</div>
    </div>)}
  </div>;
}

// ─── NOTES ──────────────────────────────────────────────────────────────
function NotesView(){
  const [text,setText]=useState("## Investigation Notes — Project Meridian\n\nKey question: Who is the ultimate beneficial owner behind Meridian Holdings?\n\nWebb appears as sole director but the pattern (virtual office, nominee secretary, privacy-shielded domain) suggests he may be fronting for someone else.\n\n### Leads to pursue\n- Companies House UK — does Webb have UK directorships?\n- Kozlov appears on multiple Cyprus filings — how many entities?\n- The shared IP (185.234.XX.XX) hosts other domains — who owns them?\n\n### For the documentary\n- The Harbour Rd address is a virtual office — could film exterior\n- Herald Tribune journalist may be willing to talk on camera");
  return <div style={{flex:1,padding:16,display:"flex",flexDirection:"column"}}>
    <div style={{fontSize:14,fontWeight:600,color:P.t1,marginBottom:10}}>Case Notes</div>
    <textarea value={text} onChange={e=>setText(e.target.value)} style={{flex:1,background:P.s1,border:`1px solid ${P.b1}`,borderRadius:8,padding:14,color:P.t1,fontSize:13,lineHeight:1.6,fontFamily:"'JetBrains Mono',monospace",resize:"none",outline:"none"}}/>
  </div>;
}

// ─── ENTITY DETAIL PANEL ────────────────────────────────────────────────
function EntDetail({id,onClose}){
  const ent=ENTITIES.find(e=>e.id===id);
  const [tab,setTab]=useState("overview");
  if(!ent)return null;
  const rc=CLAIMS.filter(c=>c.subj===ent.name||c.obj===ent.name);
  const re=EVIDENCE.filter(ev=>ev.linked.some(cid=>rc.some(c=>c.id===cid)));
  const connections=EDGES.filter(e=>e.f===id||e.t===id).map(e=>{
    const otherId=e.f===id?e.t:e.f;const other=ENTITIES.find(x=>x.id===otherId);
    return{label:e.l,entity:other,dir:e.f===id?"out":"in"};
  });

  return <div style={{width:300,background:P.s1,borderLeft:`1px solid ${P.b1}`,display:"flex",flexDirection:"column",overflow:"hidden",flexShrink:0}}>
    {/* Header */}
    <div style={{padding:"12px 14px",borderBottom:`1px solid ${P.b1}`,flexShrink:0}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:6}}>
        <TypeTag type={ent.type}/>
        <button onClick={onClose} style={{background:"transparent",border:"none",color:P.t3,cursor:"pointer",fontSize:16}}>×</button>
      </div>
      <div style={{fontSize:15,fontWeight:600,color:P.t1}}>{ent.name}</div>
      {ent.flag&&<div style={{marginTop:6,background:ent.flag==="subject"?P.redBg:P.ambBg,border:`1px solid ${ent.flag==="subject"?P.red:P.amb}25`,borderRadius:4,padding:"4px 8px",fontSize:10,color:ent.flag==="subject"?P.red:P.amb,display:"flex",alignItems:"center",gap:4}}>
        ⚑ {ent.flag==="subject"?"Investigation subject":"Key entity"}
      </div>}
    </div>
    {/* Tabs */}
    <div style={{display:"flex",borderBottom:`1px solid ${P.b1}`,flexShrink:0}}>
      {["overview","claims","evidence","links"].map(t=><Tab key={t} active={tab===t} onClick={()=>setTab(t)}>{t.charAt(0).toUpperCase()+t.slice(1)}</Tab>)}
    </div>
    {/* Content */}
    <div style={{flex:1,overflow:"auto",padding:12}}>
      {tab==="overview"&&<>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,marginBottom:12}}>
          {[["Claims",ent.claims],["Connections",ent.connections]].map(([l,v])=>
            <div key={l} style={{background:P.s3,borderRadius:6,padding:"8px 10px"}}><div style={{fontSize:17,fontWeight:700,color:P.t1}}>{v}</div><div style={{fontSize:10,color:P.t3}}>{l}</div></div>
          )}
        </div>
        <div style={{fontSize:10,color:P.t4,textTransform:"uppercase",letterSpacing:".05em",marginBottom:3}}>First Seen</div>
        <div style={{fontSize:12,color:P.t1,fontFamily:"monospace",marginBottom:12}}>{ent.firstSeen}</div>
        <div style={{fontSize:10,color:P.t4,textTransform:"uppercase",letterSpacing:".05em",marginBottom:3}}>Notes</div>
        <div style={{fontSize:12,color:P.t2,lineHeight:1.5,marginBottom:12}}>{ent.notes}</div>
        <Btn small style={{width:"100%",justifyContent:"center"}}>Edit Notes</Btn>
      </>}
      {tab==="claims"&&<div style={{display:"flex",flexDirection:"column",gap:6}}>
        {rc.length===0&&<div style={{fontSize:12,color:P.t4,padding:10}}>No claims yet</div>}
        {rc.map(c=><div key={c.id} style={{background:P.s3,borderRadius:6,padding:8}}>
          <div style={{fontSize:11,color:P.t2,lineHeight:1.4,marginBottom:4}}>
            <span style={{color:c.subj===ent.name?P.t1:P.acc,fontWeight:500}}>{c.subj}</span>
            <span style={{color:P.t4}}> {c.pred} </span>
            <span style={{color:c.obj===ent.name?P.t1:P.pur,fontWeight:500}}>{c.obj}</span>
          </div>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <Badge status={c.status}/><Conf v={c.conf} w={70}/>
          </div>
        </div>)}
      </div>}
      {tab==="evidence"&&<div style={{display:"flex",flexDirection:"column",gap:4}}>
        {re.length===0&&<div style={{fontSize:12,color:P.t4,padding:10}}>No linked evidence</div>}
        {re.map(ev=><div key={ev.id} style={{background:P.s3,borderRadius:6,padding:8}}>
          <div style={{fontSize:11,color:P.t1,fontWeight:500}}>{ev.title}</div>
          <div style={{display:"flex",justifyContent:"space-between",marginTop:4}}>
            <span style={{fontSize:10,color:P.t3}}>{ev.captured}</span>
            <span style={{fontSize:10,color:P.t4,fontFamily:"monospace"}}>{ev.hash.slice(0,12)}</span>
          </div>
        </div>)}
      </div>}
      {tab==="links"&&<div style={{display:"flex",flexDirection:"column",gap:4}}>
        {connections.length===0&&<div style={{fontSize:12,color:P.t4,padding:10}}>No connections</div>}
        {connections.map((conn,i)=><div key={i} style={{background:P.s3,borderRadius:6,padding:8,display:"flex",alignItems:"center",gap:8}}>
          <span style={{fontSize:10,color:conn.dir==="out"?P.acc:P.pur,fontWeight:600}}>{conn.dir==="out"?"→":"←"}</span>
          <div style={{flex:1}}>
            <div style={{fontSize:11,color:P.t1,fontWeight:500}}>{conn.entity?.name||"Unknown"}</div>
            <div style={{fontSize:10,color:P.t3}}>{conn.label}</div>
          </div>
          {conn.entity&&<TypeTag type={conn.entity.type}/>}
        </div>)}
      </div>}
    </div>
  </div>;
}

// ─── SPLIT PANEL LAYOUT ─────────────────────────────────────────────────
function SplitLayout({top,bottom}){
  const [split,setSplit]=useState(60);
  return <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
    <div style={{height:`${split}%`,overflow:"hidden",display:"flex"}}>{top}</div>
    <div style={{height:4,background:P.b1,cursor:"row-resize",flexShrink:0,display:"flex",alignItems:"center",justifyContent:"center"}}
      onMouseDown={e=>{const startY=e.clientY;const startSplit=split;const move=ev=>{const dy=ev.clientY-startY;const parent=e.target.parentElement;if(parent){const pct=startSplit+(dy/parent.clientHeight)*100;setSplit(Math.max(20,Math.min(80,pct)))}};const up=()=>{window.removeEventListener("mousemove",move);window.removeEventListener("mouseup",up)};window.addEventListener("mousemove",move);window.addEventListener("mouseup",up)}}>
      <div style={{width:30,height:2,background:P.t4,borderRadius:1}}/>
    </div>
    <div style={{flex:1,overflow:"hidden",display:"flex"}}>{bottom}</div>
  </div>;
}

// ─── CASE HEADER ────────────────────────────────────────────────────────
function CaseHeader({c,onBack,splitMode,onToggleSplit}){
  return <div style={{height:40,background:P.s1,borderBottom:`1px solid ${P.b1}`,display:"flex",alignItems:"center",justifyContent:"space-between",padding:"0 12px",flexShrink:0}}>
    <div style={{display:"flex",alignItems:"center",gap:10}}>
      <button onClick={onBack} style={{background:"transparent",border:"none",color:P.t3,cursor:"pointer",fontSize:12}}>← Cases</button>
      <span style={{color:P.b2}}>|</span>
      <span style={{fontSize:13,fontWeight:600,color:P.t1}}>{c.name}</span>
      <Dot c={c.status==="active"?P.grn:P.amb} pulse={c.status==="active"}/>
    </div>
    <div style={{display:"flex",alignItems:"center",gap:12,fontSize:11,color:P.t3}}>
      <span>{c.entities} entities</span><span>{c.claims} claims</span><span>{c.evidence} evidence</span>
      <Conf v={c.confidence} w={70}/>
      <button onClick={onToggleSplit} style={{background:splitMode?P.accBg:"transparent",color:splitMode?P.acc:P.t4,border:`1px solid ${splitMode?P.acc+"40":P.b1}`,borderRadius:4,padding:"3px 8px",fontSize:10,cursor:"pointer"}}>
        {splitMode?"Single":"Split"}
      </button>
    </div>
  </div>;
}

// ─── MAIN APP ───────────────────────────────────────────────────────────
export default function App(){
  const [view,setView]=useState("home");
  const [cas,setCas]=useState(null);
  const [sel,setSel]=useState(null);
  const [split,setSplit]=useState(false);
  const [splitView,setSplitView]=useState("timeline");
  const [graphTypeFilter,setGraphTypeFilter]=useState("all");

  const openCase=c=>{setCas(c);setView("graph");setSel(null)};
  const nav=v=>{if(v==="home"){setCas(null);setSel(null)}setView(v)};
  const selEnt=id=>setSel(sel===id?null:id);

  const renderView=(v)=>{
    switch(v){
      case"home":return <CaseDash onOpen={openCase}/>;
      case"graph":return <Graph sel={sel} onSel={selEnt} onDblClick={selEnt} typeFilter={graphTypeFilter}/>;
      case"timeline":return <Timeline onSel={selEnt}/>;
      case"claims":return <ClaimsView onSel={selEnt}/>;
      case"vault":return <Vault/>;
      case"entities":return <EntTable onSel={selEnt} sel={sel}/>;
      case"agents":return <AgentsView/>;
      case"activity":return <ActivityView/>;
      case"notes":return <NotesView/>;
      default:return null;
    }
  };

  const mainContent=split&&view!=="home"?
    <SplitLayout top={renderView(view)} bottom={
      <div style={{flex:1,display:"flex",flexDirection:"column"}}>
        <div style={{display:"flex",borderBottom:`1px solid ${P.b1}`,background:P.s1,flexShrink:0}}>
          {["timeline","claims","vault","entities"].filter(v2=>v2!==view).map(v2=>
            <Tab key={v2} active={splitView===v2} onClick={()=>setSplitView(v2)}>{v2.charAt(0).toUpperCase()+v2.slice(1)}</Tab>
          )}
        </div>
        <div style={{flex:1,display:"flex",overflow:"hidden"}}>{renderView(splitView)}</div>
      </div>
    }/>:renderView(view);

  return <div style={{display:"flex",height:"100vh",width:"100vw",background:P.bg,color:P.t1,fontFamily:"'Inter',-apple-system,sans-serif",fontSize:13,overflow:"hidden"}}>
    <Sidebar view={view} onNav={nav} hasCase={!!cas}/>
    <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
      {cas&&view!=="home"&&<CaseHeader c={cas} onBack={()=>nav("home")} splitMode={split} onToggleSplit={()=>setSplit(!split)}/>}
      <div style={{flex:1,display:"flex",overflow:"hidden"}}>
        {mainContent}
        {sel&&view!=="home"&&view!=="vault"&&<EntDetail id={sel} onClose={()=>setSel(null)}/>}
      </div>
    </div>
  </div>;
}
