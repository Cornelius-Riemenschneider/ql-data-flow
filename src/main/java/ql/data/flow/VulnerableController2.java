package ql.data.flow;

import java.nio.file.Paths;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class VulnerableController2 {
	public static String vulnIfTrue(String input, boolean cond) {
		if (cond) {
			return Paths.get(input).toString();
		} else {
			return "nothing";
		}
	}


	@GetMapping("/constant propagation - global")
	public String constantPropagationGlobal(
			@RequestParam(name = "name", required = false, defaultValue = "/etc/passwd") String path) {
		// requires constant propagation across procedures to avoid false positive
		//boolean b = false;
		return vulnIfTrue(path, false);
	}

}
