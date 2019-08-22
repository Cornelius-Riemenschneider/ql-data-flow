import java

import semmle.code.java.dataflow.RangeAnalysis


from Expr expr, Bound b, int delta, boolean upper, Reason r 
where 
	bounded(expr, b, delta, upper, r)
	and expr.getProperExpr().toString() = "j"
select expr, "expr is bounded by " + delta + " and upper" + upper + 
" by reason: " + r
