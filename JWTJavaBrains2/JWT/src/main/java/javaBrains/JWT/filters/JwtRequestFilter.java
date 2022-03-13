package javaBrains.JWT.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javaBrains.JWT.services.MyUserDetailsService;
import javaBrains.JWT.util.JwtUtil;

//OncePerRF filters through all requests going through
//make this component as this needs to be in Spring's radar in order to autowire
@Component
public class JwtRequestFilter extends OncePerRequestFilter{
    
    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    private JwtUtil jwtUtil;



    //Filterchain can end request at this filter or pass it on
    //this method examines incoming req for jwt in header + valid. If true get user details and save in security content
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) 
        throws ServletException, IOException{
            final String authorizationHeader = request.getHeader("Authorization");

            String username = null;
            String jwt = null;

            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
                jwt = authorizationHeader.substring(7);
                username = jwtUtil.extractUsername(jwt);
            }
            
            //even though get username from jwt, need to simulate putting into SCH only if context does not 
            //already have an authenticated user
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null){
                UserDetails userDetails = this.myUserDetailsService.loadUserByUsername(username);

                //validate jwt token using userdetails. Below code only works if jwt is valid
                if(jwtUtil.validateToken(jwt, userDetails)){
                    //everything here is what would have happened by default. We did this because we took over
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                }
            }
            //handing off control to next filter chain
            chain.doFilter(request, response);
    }
}
